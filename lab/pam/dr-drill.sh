#!/usr/bin/env bash
# =============================================================================
# dr-drill.sh - timed disaster-recovery drill for the Vault HA cluster
# (a "restore the vault from backup" test).
# Measures the two numbers a DR plan is judged on, by doing it:
#
#   RPO  data written AFTER the last snapshot is lost. The drill writes one
#        marker before the snapshot and one after, and proves the second is
#        gone after the restore - the honest demonstration of what snapshot
#        frequency buys.
#   RTO  wall-clock time from "all three nodes and their disks are gone" to
#        "a rebuilt cluster serves the data again".
#
#   1. precheck: 3 voters, autopilot healthy (./vault-ha.sh up)
#   2. write ha-test/dr-marker (random check value) + policy dr-drill-check
#   3. raft snapshot from the leader -> .secrets/ha/snapshots/ (0600), sha256
#   4. write ha-test/after-snapshot (must NOT survive)
#   5. DISASTER: delete vault-1/2/3 containers AND their volumes (the
#      unsealer survives - in production that is Azure Key Vault, which is
#      zone-redundant and outside the blast radius of the cluster)
#   6. rebuild: a fresh vault-1, init a NEW one-node cluster, `raft snapshot
#      restore -force` on it (-force: the snapshot's keyring belongs to the
#      old cluster; the shared transit seal is what lets it decrypt),
#      restart vault-1 so Raft's transport loads the restored TLS keyring,
#      THEN fresh vault-2/3 join it; wait for 3 healthy voters
#   7. verify with the OLD root token (restored with the data): dr-marker
#      matches, dr-drill-check policy present, after-snapshot absent
#   8. report: out/dr-drill-<stamp>.{md,json} (+ dr-drill-latest.*), exit 1
#      if verification failed or RTO exceeded --target-rto (default 300 s)
#
# Afterwards the OLD recovery key and root token (.secrets/ha/init.json) are
# the valid ones again: the restore brought back the old keyring, so the new
# cluster's init output is discarded.
#
#   9. --evidence-dir DIR: the run record - dr-drill.json + dr-drill.md (no
#      secret: marker VALUES never leave Vault, only PASS/FAIL) and the code
#      fingerprint (code.sha256sums from lib.sh code_sums, taken at the
#      start; dr-drill.json carries its hash), sealed with
#      SHA256SUMS after a secret-shape / local-path check; relative DIR is
#      taken from lab/pam (e.g. ../evidence/pam-dr/<UTC>). Written for a
#      drill whose verification failed too (marked failed); a drill that
#      dies before step 7 writes none - under test/e2e.sh that abort is in
#      e2e's own (failed) run record. --verify DIR re-checks one with only
#      jq + shasum (no Docker).
#
# Usage: ./dr-drill.sh [--target-rto SECONDS] [--evidence-dir DIR]
#        ./dr-drill.sh --verify DIR
# =============================================================================
source "$(dirname "$0")/lib.sh"
# shellcheck source=ha/ha-lib.sh
source "$PAM_DIR/ha/ha-lib.sh"
# Dependencies are checked after the arguments: --verify needs no Docker.

TARGET_RTO=300 EVIDENCE_DIR="" VERIFY_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-rto) TARGET_RTO="${2:?--target-rto SECONDS}"; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR="${2:?--evidence-dir DIR}"; shift 2 ;;
    --verify) VERIFY_DIR="${2:?--verify DIR}"; shift 2 ;;
    *) die "usage: $0 [--target-rto SECONDS] [--evidence-dir DIR] | --verify DIR" ;;
  esac
done
if [[ -n "$VERIFY_DIR" ]]; then
  need jq; need shasum
  run_record_verify "$VERIFY_DIR" dr-drill.json '[.checks[]] | all(. == "PASS")' && { log "DR-DRILL VERIFY PASSED ($(basename "$VERIFY_DIR"))"; exit 0; }
  echo "DR-DRILL VERIFY FAILED"; exit 1
fi
need docker; need jq; need perl; need openssl
if [[ -n "$EVIDENCE_DIR" ]]; then
  need shasum; need git
  # The code this drill uses, fingerprinted BEFORE it starts.
  code_dir=$(mktemp -d); chmod 700 "$code_dir"
  code_sums > "$code_dir/code.sha256sums" || { rm -rf "$code_dir"; die "could not fingerprint lab/pam (needs a git checkout) - no run record without it"; }
  code_json=$(code_meta "$code_dir/code.sha256sums")
fi
[[ -s "$HA_DIR/init.json" ]] || die "no HA cluster - ./vault-ha.sh up first"

export VAULT_TOKEN; VAULT_TOKEN=$(ha_root)
ha_healthy || die "cluster not healthy - ./vault-ha.sh status"
out_dir
ts=$(stamp)
t_start=$(now_ms)
timeline=()
mark() { timeline+=("$(date -u +%H:%M:%S)|$1"); log "DR: $1"; }

# --- 2. state that must survive ----------------------------------------------
leader=$(ha_leader)
marker=$(openssl rand -hex 16)
ha_cli "$leader" kv put ha-test/dr-marker value="$marker" </dev/null >/dev/null
printf 'path "ha-test/data/dr-marker" { capabilities = ["read"] }\n' \
  | ha_cli "$leader" policy write dr-drill-check - >/dev/null
mark "markers written on $leader (ha-test/dr-marker, policy dr-drill-check)"

# --- 3. snapshot ----------------------------------------------------------------
snap="$HA_DIR/snapshots/dr-$ts.snap"
t0=$(now_ms)
ha_snapshot "$leader" "$snap"
snap_secs=$(secs_since "$t0")
t_snap=$(now_ms)
snap_sha=$(openssl dgst -sha256 -r "$snap" | cut -d' ' -f1)
snap_size=$(wc -c < "$snap" | tr -d ' ')
mark "snapshot saved in ${snap_secs}s ($snap_size bytes, sha256 ${snap_sha:0:16}...)"

# --- 4. a write the snapshot does not contain ----------------------------------------
sleep 2
ha_cli "$leader" kv put ha-test/after-snapshot value=lost-on-restore </dev/null >/dev/null
mark "post-snapshot write ha-test/after-snapshot (expected to be LOST)"

# --- 5. disaster ------------------------------------------------------------------------
t_dis=$(now_ms)
rpo=$(awk -v a="$t_snap" -v b="$t_dis" 'BEGIN { printf "%.1f", (b - a) / 1000 }')
ha rm -sf "${HA_NODES[@]}" >/dev/null 2>&1
for n in "${HA_NODES[@]}"; do docker volume rm -f "contoso-pam-ha_${n}-data" >/dev/null; done
mark "DISASTER: vault-1/2/3 containers and volumes destroyed"

# --- 6. rebuild + restore ---------------------------------------------------------------
# Restore into a ONE-node cluster, then let the other two join it. If all
# three nodes form the new cluster first, the followers keep the new
# cluster's Raft TLS keyring in memory while the restore brings back the old
# one, and the next restart of any node splits the cluster ("tls:
# unrecognized name" - found the hard way by ./vault-ha.sh upgrade right
# after a drill). Joining after the restore hands them the restored keyring.
ha up -d vault-1 >/dev/null 2>&1
export VAULT_TOKEN=""
ha_wait 90 "vault-1 API on the rebuilt cluster" ha_api_up vault-1
# Kept (0600) until the restore succeeds: if the drill dies between init and
# restore, this is the only token that can finish the restore by hand.
ha_cli vault-1 operator init -recovery-shares=1 -recovery-threshold=1 -format=json </dev/null > "$HA_DIR/rebuild-init.json"
mark "new cluster initialised on vault-1"
export VAULT_TOKEN; VAULT_TOKEN=$(jq -r .root_token "$HA_DIR/rebuild-init.json")
vault1_active() { [[ "$(ha_status vault-1 | jq -r '.sealed')" == false ]] && ha_cli vault-1 operator raft list-peers </dev/null >/dev/null 2>&1; }
ha_wait 90 "vault-1 unsealed and leading" vault1_active
ha cp "$snap" vault-1:/tmp/restore.snap >/dev/null 2>&1 || die "could not copy the snapshot into vault-1"
# docker cp lands the file as root, mode 0600: hand it to the vault user.
ha exec -T -u 0 vault-1 chown vault /tmp/restore.snap </dev/null
t0=$(now_ms)
ha_cli vault-1 operator raft snapshot restore -force /tmp/restore.snap </dev/null >/dev/null
ha exec -T -u 0 vault-1 rm -f /tmp/restore.snap </dev/null || true
rm -f "$HA_DIR/rebuild-init.json"   # the restore replaced that cluster's keyring: its token is dead now
mark "snapshot restored (-force) in $(secs_since "$t0")s on a one-node cluster"
# From here the restored keyring and token store are live: the OLD root token works.
export VAULT_TOKEN; VAULT_TOKEN=$(ha_root)
# Restart vault-1 once so its Raft transport also loads the RESTORED TLS
# keyring; joining nodes before that fail with "tls: unrecognized name"
# (verified on Vault 2.1.1 - verify: HashiCorp's restore runbook for your
# version). It auto-unseals through the transit seal.
ha restart vault-1 >/dev/null 2>&1
ha_wait 90 "vault-1 active again after the restart" vault1_active
ha up -d vault-2 vault-3 >/dev/null 2>&1
mark "vault-1 restarted on the restored keyring; vault-2/3 rebuilt and joining"

ha_wait 180 "3 healthy voters serving the restored data" ha_healthy
got=$(ha_cli "$(ha_any_node)" kv get -field=value ha-test/dr-marker </dev/null 2>/dev/null || true)
t_rec=$(now_ms)
rto=$(awk -v a="$t_dis" -v b="$t_rec" 'BEGIN { printf "%.1f", (b - a) / 1000 }')
mark "RECOVERED: data served again (RTO ${rto}s)"

# --- 7. verify ---------------------------------------------------------------------------
fails=0
v_marker=FAIL v_policy=FAIL v_lost=FAIL v_rto=FAIL
[[ -n "$got" && "$got" == "$marker" ]] && v_marker=PASS || fails=$((fails + 1))
ha_cli "$(ha_any_node)" policy read dr-drill-check </dev/null >/dev/null 2>&1 && v_policy=PASS || fails=$((fails + 1))
lost_rc=0; ha_cli "$(ha_any_node)" kv get ha-test/after-snapshot </dev/null >/dev/null 2>&1 || lost_rc=$?
[[ $lost_rc -eq 2 ]] && v_lost=PASS || fails=$((fails + 1))   # kv get: 2 = not found
awk -v r="$rto" -v t="$TARGET_RTO" 'BEGIN { exit !(r <= t) }' && v_rto=PASS || fails=$((fails + 1))
versions=$(for n in "${HA_NODES[@]}"; do printf '%s=%s ' "$n" "$(ha_version "$n")"; done)

# --- 8. report ---------------------------------------------------------------------------
json=$(jq -n --arg ts "$(date -u +%FT%TZ)" --arg rto "$rto" --arg rpo "$rpo" --arg tr "$TARGET_RTO" \
  --arg snap "$(basename "$snap")" --arg sha "$snap_sha" --arg size "$snap_size" --arg ss "$snap_secs" \
  --arg vm "$v_marker" --arg vp "$v_policy" --arg vl "$v_lost" --arg vr "$v_rto" --arg ver "$versions" \
  --arg total "$(secs_since "$t_start")" --argjson code "${code_json:-null}" \
  '{schema: "contoso-pam/dr-drill/v2", generated_at: $ts, rto_seconds: ($rto | tonumber), rpo_seconds: ($rpo | tonumber), target_rto_seconds: ($tr | tonumber),
    drill_seconds: ($total | tonumber), snapshot: {file: $snap, sha256: $sha, bytes: ($size | tonumber), seconds: ($ss | tonumber)},
    checks: {marker_restored: $vm, policy_restored: $vp, post_snapshot_write_lost: $vl, rto_within_target: $vr},
    rpo_note: "set by this drill: its own 2 s pause between the snapshot and the disaster. It shows the mechanism (writes after the last snapshot are lost); a planning RPO is the snapshot interval.",
    versions: $ver} + (if $code == null then {} else {code: $code} end)')
printf '%s\n' "$json" > "$OUT/dr-drill-$ts.json"
{
  printf '# Vault DR drill - %s\n\n' "$(date -u +%FT%TZ)"
  printf 'Lab: 3-node Raft cluster on one Docker host, transit auto-unseal (stand-in for Azure Key Vault). %s\n\n' "$versions"
  printf '| Measure | Result |\n|---|---|\n'
  printf '| **RTO** (disks gone -> data served) | **%ss** (target %ss: %s) |\n' "$rto" "$TARGET_RTO" "$v_rto"
  printf '| **RPO** (snapshot age at the disaster) | **%ss** - writes in that window are lost. Set by the drill'"'"'s own 2 s pause, so it shows the mechanism, not a planning RPO (that is the snapshot interval) |\n' "$rpo"
  # shellcheck disable=SC2016 # backticks are markdown code spans, not command substitution
  printf '| Snapshot | %s, %s bytes, %ss, sha256 `%s` |\n' "$(basename "$snap")" "$snap_size" "$snap_secs" "$snap_sha"
  printf '| Marker written before the snapshot: restored | %s |\n' "$v_marker"
  printf '| Policy written before the snapshot: restored | %s |\n' "$v_policy"
  printf '| Write made after the snapshot: gone after the restore | %s |\n\n' "$v_lost"
  printf '## Timeline (UTC)\n\n| Time | Step |\n|---|---|\n'
  printf '%s\n' "${timeline[@]}" | awk -F'|' '{ printf "| %s | %s |\n", $1, $2 }'
  printf '\nProduction differences: nodes in three availability zones, TLS, recovery keys 3-of-5 with custodians, snapshots on a schedule to immutable storage (the evidence-store WORM container), and the restore rehearsed on an isolated network.\n'
} > "$OUT/dr-drill-$ts.md"
cp "$OUT/dr-drill-$ts.md" "$OUT/dr-drill-latest.md"
cp "$OUT/dr-drill-$ts.json" "$OUT/dr-drill-latest.json"
log "DR drill: RTO ${rto}s (target ${TARGET_RTO}s) RPO ${rpo}s - marker $v_marker, policy $v_policy, post-snapshot write lost $v_lost, RTO $v_rto"
log "Report: $OUT/dr-drill-$ts.md"
if [[ -n "$EVIDENCE_DIR" ]]; then
  stage=$(mktemp -d); chmod 700 "$stage"
  cp "$OUT/dr-drill-$ts.json" "$stage/dr-drill.json"; cp "$OUT/dr-drill-$ts.md" "$stage/dr-drill.md"
  cp "$code_dir/code.sha256sums" "$stage/code.sha256sums"
  if run_record_seal "$stage" "$EVIDENCE_DIR" dr-drill.json dr-drill.md code.sha256sums; then log "run record: $EVIDENCE_DIR (dr-drill.json, dr-drill.md, code.sha256sums, SHA256SUMS)"
  else fails=$((fails + 1)); fi
  rm -rf "$stage" "$code_dir"
fi
[[ $fails -eq 0 ]] || die "DR drill verification failed ($fails check(s))"
