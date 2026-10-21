#!/usr/bin/env bash
# Shared helpers for the Vault HA cluster scripts (vault-ha.sh, dr-drill.sh).
# Sourced after ../lib.sh, never executed. Everything secret lives in
# .secrets/ha/ (0700): unsealer-init.json, init.json (recovery key + root
# token of the cluster), seal.hcl (transit token), snapshots/.

HA_DIR=.secrets/ha
HA_NODES=(vault-1 vault-2 vault-3)

ha() { docker compose -f docker-compose.ha.yml --env-file "$HA_DIR/ha.env" "$@"; }

# Vault CLI inside a node. As in lib.sh, `-e VAULT_TOKEN` forwards the
# caller's exported token without putting it in docker's argv. Callers
# always export VAULT_TOKEN (possibly empty) before using it.
ha_cli() { local node="$1"; shift; ha exec -T -e VAULT_TOKEN "$node" vault "$@"; }

ha_root()     { jq -r '.root_token' "$HA_DIR/init.json"; }
ha_running()  { [[ "$(ha ps "$1" --format '{{.State}}' 2>/dev/null)" == running ]]; }
now_ms()      { perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000' 2>/dev/null || echo "$(date +%s)000"; }
secs_since()  { awk -v a="$1" -v b="$(now_ms)" 'BEGIN { printf "%.1f", (b - a) / 1000 }'; }

ha_status() { # ha_status NODE -> `vault status -format=json` (exit 2 = sealed is still an answer)
  local out rc=0
  out=$(VAULT_TOKEN="" ha_cli "$1" status -format=json </dev/null 2>/dev/null) || rc=$?
  [[ $rc -eq 0 || $rc -eq 2 ]] || return 1
  printf '%s' "$out"
}
ha_unsealed()    { [[ "$(ha_status "$1" | jq -r '.sealed' 2>/dev/null)" == false ]]; }
ha_initialized() { [[ "$(ha_status "$1" | jq -r '.initialized' 2>/dev/null)" == true ]]; }
ha_version()     { ha_status "$1" | jq -r '.version'; }

ha_any_node() { # first running, unsealed node (for cluster-wide queries)
  local n
  for n in "${HA_NODES[@]}"; do ha_running "$n" && ha_unsealed "$n" && { echo "$n"; return 0; }; done
  return 1
}

ha_peers() { # raft peer list as JSON (needs VAULT_TOKEN = cluster root)
  local n
  n=$(ha_any_node) || return 1
  ha_cli "$n" operator raft list-peers -format=json </dev/null 2>/dev/null | jq -c '.data.config.servers'
}

ha_leader() { ha_peers | jq -r '.[] | select(.leader == true) | .node_id' 2>/dev/null; }

ha_healthy() { # 3 voters, all unsealed, autopilot healthy (needs the root token exported)
  local n peers ap
  for n in "${HA_NODES[@]}"; do ha_running "$n" && ha_unsealed "$n" || return 1; done
  peers=$(ha_peers) || return 1
  [[ "$(printf '%s' "$peers" | jq '[.[] | select(.voter == true)] | length')" -eq 3 ]] || return 1
  n=$(ha_any_node) || return 1
  ap=$(ha_cli "$n" operator raft autopilot state -format=json </dev/null 2>/dev/null) || return 1
  [[ "$(printf '%s' "$ap" | jq -r '.Healthy')" == true ]]
}

ha_wait() { # ha_wait SECONDS DESCRIPTION CMD... : poll CMD every second until it succeeds
  local limit="$1" what="$2" i; shift 2
  for ((i = 0; i < limit; i++)); do "$@" && return 0; sleep 1; done
  die "timed out after ${limit}s waiting for: $what"
}

ha_snapshot() { # ha_snapshot NODE DEST : raft snapshot taken on NODE (the leader), copied to DEST (0600)
  local leader="$1" dest="$2"
  ha_cli "$leader" operator raft snapshot save /tmp/ha.snap </dev/null >/dev/null
  ha cp "$leader:/tmp/ha.snap" "$dest" >/dev/null 2>&1 || die "could not copy the snapshot out of $leader"
  ha exec -T "$leader" rm -f /tmp/ha.snap </dev/null
  chmod 600 "$dest"
}

ha_api_up() { ha_status "$1" >/dev/null; }   # the node answers (sealed or not)
