#!/usr/bin/env bash
# =============================================================================
# run.sh - run every lab/kql detection on a real Kusto engine: the Azure Data
# Explorer Kusto emulator ("Kustainer") in a local container. One command,
# once the operator has read Microsoft's licence terms and accepts them:
#
#   lab/monitoring/kusto-harness/run.sh --accept-eula
#
# Without --accept-eula it prints the licence URL and a summary and exits 2
# BEFORE touching Docker: nothing is pulled, nothing is started, ACCEPT_EULA
# is never set. No environment variable can stand in for the flag.
#
# Steps (README.md has the detail):
#   1. harness.py check - offline validation of schemas, shims and cases
#   2. preflight - docker reachable (starts a STOPPED colima with Rosetta);
#      on an arm64 host, amd64 emulation present; shared Docker: waits while
#      another lab stack (contoso-pam*, contoso-dyndb*, pam-scale*) runs,
#      polling every 60 s, up to 45 min; never stops anyone else's container
#   3. docker pull + run of the pinned emulator image, linux/amd64,
#      ACCEPT_EULA=Y, -m 4g, port bound to 127.0.0.1 only
#   4. harness.py wait, then harness.py run (database, tables, shims, engine
#      probes, every case of every rule)
#   5. container removed (unless --keep); the record - pass, fail, or an engine
#      that never started - goes to lab/evidence/kusto/<UTC ts>/ + SHA256SUMS
#
# Usage: run.sh --accept-eula [--keep] [--no-publish] [--port N]
#               [--rules a,b] [--case RULE/ID] [--image REF] [--memory 4g]
#               [--wait-max SECONDS]
#        run.sh --help
# Exit: 0 every rule passed · 1 a rule failed · 2 refused / preflight failed /
#       engine did not start (that record is still published)
# =============================================================================
set -euo pipefail
umask 022

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$HARNESS_DIR/../.." && pwd)"
EVIDENCE_ROOT="$LAB_DIR/evidence/kusto"

# The image Microsoft Learn's "Install the Azure Data Explorer Kusto
# emulator" (ms.date 2026-07-23) names, mcr.microsoft.com/azuredataexplorer/
# kustainer-linux:latest, pinned to the digest :latest resolved to on
# 2026-10-20 (a single linux/amd64 manifest, image label build
# 2026.10.20.1140-2642-34f1c8c-master; the :stable tag Learn also mentions
# returned MANIFEST_UNKNOWN that day). Override with --image; the run
# record names the image and digest that actually ran.
IMAGE_DEFAULT="mcr.microsoft.com/azuredataexplorer/kustainer-linux@sha256:d5981f2bc0a07b692bbc6c1331c66c50bf65a80896e05457e6e9d789628d8c60"
LICENSE_URL="https://aka.ms/adx.emulator.license"
LICENSE_PDF="https://kustoes.blob.core.windows.net/kusto/ADX-Emulator-Evaluation-Terms.pdf"
OTHER_STACKS='^(contoso-pam|contoso-dyndb|pam-scale)'

ACCEPT=0
KEEP=0
PUBLISH=1
PORT=""
RULES=""
CASE=""
IMAGE="$IMAGE_DEFAULT"
MEMORY="4g"
WAIT_MAX=2700
READY_MAX=1200
TS="$(date -u +%Y%m%dT%H%M%SZ)"
CNAME="contoso-kusto-harness-${TS}"
WORK=""
STARTED_CONTAINER=0
PUBLISHED=0

usage() {
    sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# No clock times on progress lines: with them a reader could derive engine
# timings, and the emulator licence (2 d) keeps benchmark results private.
# The run id (UTC start) and results.json started/finished say when it ran.
log() {
    local line
    line="run.sh: $*"
    printf '%s\n' "$line"
    if [[ -n "$WORK" && -d "$WORK" ]]; then
        printf '%s\n' "$line" >>"$WORK/run.log"
    fi
}

die() {
    log "ERROR: $*"
    exit 2
}

eula_notice() {
    cat <<EOF
run.sh: refusing to start - the Kusto emulator is licensed software and
running it means accepting Microsoft's licence terms (docker run -e ACCEPT_EULA=Y).

  Licence:  ${LICENSE_URL}
            (redirects to ${LICENSE_PDF})

  In short (read the full terms - this is not legal advice):
    1. Free, for internal business use on your own devices only: not in a live
       (production) environment, and not for commercial, non-profit or
       revenue-generating activities.
    2. No reverse engineering, no sharing or redistributing the software, and
       no disclosing benchmark-test results to third parties without Microsoft's
       written approval (the run record therefore keeps no timings).
    3. Provided as is: no warranty, no support obligation, damages limited to
       US\$5; US / Canada: your state or province's law, King County WA venue.

Nothing was pulled or started. To accept the terms and run:

  ${BASH_SOURCE[0]} --accept-eula
EOF
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    else
        shasum -a 256 "$1"
    fi
}

# Copy the working record to lab/evidence/kusto/<ts>/ with guids.txt and
# SHA256SUMS (or leave it in $WORK with --no-publish). Pass or fail alike.
publish_record() {
    if [[ $PUBLISH -ne 1 ]]; then
        log "--no-publish: run record left in ${WORK}"
        return 0
    fi
    DEST="$EVIDENCE_ROOT/$TS"
    if [[ -e "$DEST" ]]; then
        log "ERROR: refusing to overwrite ${DEST}; record left in ${WORK}"
        return 1
    fi
    mkdir -p "$DEST"
    cp -R "$WORK"/. "$DEST"/
    # Engine messages can carry request / activity ids: list every GUID-shaped
    # value the inputs do not contain, like the lab's other run records.
    if ! python3 "$HARNESS_DIR/harness.py" guids --record-dir "$DEST"; then
        log "WARNING: harness.py guids failed - check the record against the public GUID gate by hand"
    fi
    (
        cd "$DEST"
        find . -type f -print | LC_ALL=C sort | sed 's|^\./||' |
            while IFS= read -r f; do sha256_of "$f"; done
    ) >"$WORK/.sha256sums"
    mv "$WORK/.sha256sums" "$DEST/SHA256SUMS"
    PUBLISHED=1
    log "run record published: ${DEST} ($(wc -l <"$DEST/SHA256SUMS" | tr -d ' ') files in SHA256SUMS)"
}

# The container exited or never answered (e.g. the engine needs a CPU
# feature amd64 emulation does not provide): keep its log, write a record
# that says so - every rule NOT RUN, nothing passed or failed - publish it,
# and stop. No retry: rerunning cannot change the host's CPU.
engine_start_failed() {
    docker logs --tail 80 "$CNAME" >"$WORK/engine.log" 2>&1 || true
    cat "$WORK/engine.log"
    log "ERROR: $1 (engine.log above)"
    # Exits 1 by design (the result is not PASS); the record is what counts.
    python3 "$HARNESS_DIR/harness.py" run --endpoint "$ENDPOINT" --record-dir "$WORK" \
        --container "$CNAME" --image "$IMAGE" --accept-eula-recorded --engine-start-failed "$1" || true
    if [[ -f "$WORK/results.json" ]]; then
        publish_record || true
    else
        log "harness.py wrote no failure record; working files in ${WORK}"
    fi
    exit 2
}

# Invoked through `trap cleanup EXIT`, which ShellCheck cannot follow.
# shellcheck disable=SC2329
cleanup() {
    local rc=$?
    if [[ $STARTED_CONTAINER -eq 1 ]]; then
        if [[ $KEEP -eq 1 ]]; then
            log "--keep: container ${CNAME} left running on 127.0.0.1:${PORT} (remove: docker rm -f ${CNAME})"
        else
            docker rm -f "$CNAME" >/dev/null 2>&1 || true
            log "removed container ${CNAME}"
        fi
    fi
    if [[ -n "$WORK" && -d "$WORK" ]]; then
        if [[ $PUBLISHED -eq 1 ]]; then
            rm -rf "$WORK"
        else
            printf 'run.sh: working files kept in %s\n' "$WORK"
        fi
    fi
    exit "$rc"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --accept-eula) ACCEPT=1 ;;
        --keep) KEEP=1 ;;
        --no-publish) PUBLISH=0 ;;
        --port) PORT="${2:?--port needs a value}"; shift ;;
        --rules) RULES="${2:?--rules needs a value}"; shift ;;
        --case) CASE="${2:?--case needs a value}"; shift ;;
        --image) IMAGE="${2:?--image needs a value}"; shift ;;
        --memory) MEMORY="${2:?--memory needs a value}"; shift ;;
        --wait-max) WAIT_MAX="${2:?--wait-max needs a value}"; shift ;;
        -h | --help) usage; exit 0 ;;
        *) printf 'run.sh: unknown argument %s (see --help)\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

# --- 0. the licence gate: before anything touches Docker ---------------------
if [[ $ACCEPT -ne 1 ]]; then
    eula_notice
    exit 2
fi

trap cleanup EXIT
WORK="$(mktemp -d "${TMPDIR:-/tmp}/contoso-kusto-harness.XXXXXX")"
log "run ${TS}: operator passed --accept-eula (licence ${LICENSE_URL})"
log "args: keep=${KEEP} publish=${PUBLISH} rules=${RULES:-all} case=${CASE:-all} image=${IMAGE} memory=${MEMORY}"

# --- 1. offline validation -----------------------------------------------------
command -v python3 >/dev/null 2>&1 || die "python3 not found"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "python3 3.9+ needed"
if ! python3 "$HARNESS_DIR/harness.py" check >"$WORK/check.txt" 2>&1; then
    cat "$WORK/check.txt"
    die "harness.py check failed - nothing was started"
fi
log "harness.py check: $(tail -n 1 "$WORK/check.txt")"

# --- 2. preflight --------------------------------------------------------------
# The lab Mac keeps docker / colima in ~/.local/bin, which a non-login shell
# may not have on PATH (same rule as lab/k8s/ci/pipeline.sh).
if [[ -d "$HOME/.local/bin" && ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    PATH="$PATH:$HOME/.local/bin"
fi
command -v docker >/dev/null 2>&1 || die "docker not found"
if ! docker info >/dev/null 2>&1; then
    if command -v colima >/dev/null 2>&1 && ! colima status >/dev/null 2>&1; then
        log "docker unreachable and colima stopped: colima start --vm-type vz --vz-rosetta"
        colima start --vm-type vz --vz-rosetta
    fi
    docker info >/dev/null 2>&1 || die "docker daemon unreachable"
fi
ARCH="$(docker info --format '{{.Architecture}}')"
log "docker server: $(docker version --format '{{.Server.Version}}') ${ARCH}"
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    # The emulator publishes linux/amd64 only (registry manifest) and Learn
    # says ARM processors are not supported: it runs under amd64 emulation.
    if command -v colima >/dev/null 2>&1; then
        if colima ssh -- test -e /proc/sys/fs/binfmt_misc/rosetta 2>/dev/null; then
            log "amd64 emulation: colima Rosetta binfmt handler present"
        elif colima ssh -- test -e /proc/sys/fs/binfmt_misc/qemu-x86_64 2>/dev/null; then
            log "amd64 emulation: qemu only (no Rosetta) - expect a slow engine; Learn needs SSE4.2/AVX2"
        else
            die "no amd64 emulation in the colima VM. Restart it with Rosetta (stops every container in it - coordinate first): colima stop && colima start --vm-type vz --vz-rosetta"
        fi
    else
        log "arm64 Docker host without colima: relying on the runtime's amd64 emulation (Docker Desktop: Rosetta setting)"
    fi
fi
waited=0
while true; do
    others="$(docker ps --format '{{.Names}}' | grep -E "$OTHER_STACKS" || true)"
    [[ -z "$others" ]] && break
    if [[ $waited -ge $WAIT_MAX ]]; then
        die "other lab stacks still running after ${WAIT_MAX}s (not stopping them): $(printf '%s' "$others" | tr '\n' ' ')"
    fi
    log "shared Docker busy, waiting 60 s ($waited/${WAIT_MAX}s): $(printf '%s' "$others" | tr '\n' ' ')"
    sleep 60
    waited=$((waited + 60))
done
if [[ -z "$PORT" ]]; then
    PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
fi
ENDPOINT="http://127.0.0.1:${PORT}"

# --- 3. the engine -------------------------------------------------------------
log "docker pull --platform linux/amd64 ${IMAGE} (several GB on the first run)"
docker pull --platform linux/amd64 "$IMAGE" || die "docker pull failed - nothing was started"
log "starting ${CNAME} (-m ${MEMORY}, ${ENDPOINT} -> 8080)"
# Set before docker run: a container that is created but cannot start (e.g.
# the port was taken in the meantime) must still be removed by cleanup.
STARTED_CONTAINER=1
if ! docker run -d -t --name "$CNAME" --platform linux/amd64 \
    -e ACCEPT_EULA=Y -m "$MEMORY" -p "127.0.0.1:${PORT}:8080" \
    --label org.contoso.harness=kusto "$IMAGE" >/dev/null; then
    KEEP=0
    die "docker run failed (${CNAME} is removed if it was created)"
fi

ready=0
deadline=$((SECONDS + READY_MAX))
while [[ $SECONDS -lt $deadline ]]; do
    if [[ "$(docker inspect --format '{{.State.Running}}' "$CNAME" 2>/dev/null || echo false)" != "true" ]]; then
        engine_start_failed "the emulator container exited before it was ready"
    fi
    if python3 "$HARNESS_DIR/harness.py" wait --endpoint "$ENDPOINT" --timeout 15 >>"$WORK/run.log" 2>/dev/null; then
        ready=1
        break
    fi
done
if [[ $ready -ne 1 ]]; then
    engine_start_failed "the emulator did not answer .show version within ${READY_MAX}s"
fi
log "engine ready at ${ENDPOINT}"

# --- 4. the run ----------------------------------------------------------------
run_args=(run --endpoint "$ENDPOINT" --record-dir "$WORK" --container "$CNAME" --image "$IMAGE" --accept-eula-recorded)
[[ -n "$RULES" ]] && run_args+=(--rules "$RULES")
[[ -n "$CASE" ]] && run_args+=(--case "$CASE")
set +e
python3 "$HARNESS_DIR/harness.py" "${run_args[@]}"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
    docker logs --tail 200 "$CNAME" >"$WORK/engine.log" 2>&1 || true
fi
rm -f "$WORK/check.txt"

# --- 5. publish ----------------------------------------------------------------
if [[ ! -f "$WORK/results.json" ]]; then
    die "harness.py run wrote no results.json (exit ${rc}) - nothing to publish; log: ${WORK}/run.log"
fi
publish_record || die "run record not published"
exit "$rc"
