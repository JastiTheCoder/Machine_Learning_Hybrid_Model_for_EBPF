#!/usr/bin/env bash
# verify-harness.sh -- prove the capture pipeline works before any malware runs.
#
#   sudo bash scripts/capture/verify-harness.sh
#
# Every check here uses harmless packages. Run it after harden-vm.sh and after
# starting the sinkhole, and do not proceed to a malware batch until it passes.
#
# The check that matters most is #4. The monitor detects sessions passively, by
# watching for npm exec events (internal/session/detector.go), and it has never
# been exercised against an install happening inside a container. eBPF sees
# host-namespace PIDs so it should work -- but "should" is not good enough when
# the failure mode is a batch of live malware producing empty session files,
# which cannot be re-run without provisioning a new VM.
#
# Check #6 is the second-most important: it confirms a credential read inside
# the container actually reaches the feature vector. Without the decoy files in
# the image, a sample whose whole payload is "steal the SSH key" would look
# identical to a benign package.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

MONITOR_BIN="${MONITOR_BIN:-$PROJECT_ROOT/npm-ebpf-monitor}"
SESSIONS_DIR="${SESSIONS_DIR:-/var/lib/capture-harness/verify}"
MONITOR_LOG="${MONITOR_LOG:-/var/log/capture/verify-monitor.log}"
IMAGE="${IMAGE:-capture-harness:node20}"
CAPTURE_NET="${CAPTURE_NET:-capture-net}"
SINKHOLE_PORT="${SINKHOLE_PORT:-9999}"
FILTER_CHAIN="CAPTURE_FILTER"
REGISTRY_HOST="${REGISTRY_HOST:-registry.npmjs.org}"
REGISTRY_IP_FILE="/var/lib/capture-harness/registry-ips"

SETTLE_SECS="${SETTLE_SECS:-20}"
JSON_WAIT_SECS="${JSON_WAIT_SECS:-45}"

PASS=0
FAIL=0
MONITOR_PID=""

pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }
info() { echo "==> $*"; }

cleanup() {
  if [[ -n "$MONITOR_PID" ]] && kill -0 "$MONITOR_PID" 2>/dev/null; then
    kill -TERM "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
  fi
  docker ps --quiet --filter "label=capture-verify" | while read -r cid; do
    [[ -n "$cid" ]] && docker kill "$cid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT INT TERM

run_in_container() {
  docker run --rm \
    --label capture-verify \
    --network "$CAPTURE_NET" \
    --add-host "$REGISTRY_HOST:$(head -n 1 "$REGISTRY_IP_FILE" 2>/dev/null || echo 127.0.0.1)" \
    --dns 127.0.0.1 \
    --cpus 2 --memory 2g --pids-limit 512 \
    "$IMAGE" bash -lc "$1"
}

# probe_container <shell-snippet-echoing-a-token>
#
# Echoes the container's last line of output, or CONTAINER_ERROR if the
# container itself failed to run.
#
# Network checks must never be written as `if run_in_container '<probe>'`. That
# treats "the probe tool is not installed in the image" the same as "the
# network blocked it", so a missing binary reports the firewall as working --
# a false pass on exactly the check that must not be wrong. Probes here use
# bash's own /dev/tcp, which is always present, and report an explicit token so
# that anything unexpected fails rather than passes.
probe_container() {
  local out
  out=$(run_in_container "$1" 2>/dev/null | tail -n 1) || out="CONTAINER_ERROR"
  [[ -n "$out" ]] || out="CONTAINER_ERROR"
  echo "$out"
}

# tcp_probe <host> <port> -- echoes REACHABLE, BLOCKED, or CONTAINER_ERROR.
tcp_probe() {
  probe_container "if timeout 4 bash -c 'exec 3<>/dev/tcp/$1/$2' 2>/dev/null; then echo REACHABLE; else echo BLOCKED; fi"
}

wait_for_session() {
  local marker="$1" elapsed=0
  while [[ $elapsed -lt $JSON_WAIT_SECS ]]; do
    local found
    found=$(find "$SESSIONS_DIR" -maxdepth 1 -name '*.json' -newer "$marker" -print -quit 2>/dev/null || true)
    [[ -n "$found" ]] && { echo "$found"; return 0; }
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

# ---------------------------------------------------------------------------
echo "================================================================"
echo " Capture harness verification"
echo "================================================================"

[[ ${EUID} -eq 0 ]] || { echo "ERROR: must run as root"; exit 1; }
mkdir -p "$SESSIONS_DIR" "$(dirname "$MONITOR_LOG")"

# --- 1. Firewall ------------------------------------------------------------
info "1. Firewall"

if iptables -t filter -C "$FILTER_CHAIN" -d 169.254.169.254 -j DROP 2>/dev/null; then
  pass "metadata endpoint rule present"
else
  fail "metadata endpoint rule MISSING -- run harden-vm.sh"
fi

if docker network inspect "$CAPTURE_NET" >/dev/null 2>&1; then
  pass "docker network $CAPTURE_NET exists"
else
  fail "docker network $CAPTURE_NET missing -- run harden-vm.sh"
fi

# --- 2. Sinkhole ------------------------------------------------------------
info "2. Sinkhole"

if ss -lnt | grep -q ":$SINKHOLE_PORT "; then
  pass "sinkhole listening on $SINKHOLE_PORT"
else
  fail "sinkhole NOT listening -- start sinkhole.py"
fi

# --- 3. Container egress ----------------------------------------------------
info "3. Container egress policy"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  info "   building $IMAGE"
  docker build --quiet --tag "$IMAGE" "$SCRIPT_DIR" >/dev/null
fi

# The metadata endpoint must be unreachable from inside a container. This is
# the check worth being paranoid about: stealing cloud credentials needs no
# container escape, only an unfiltered route to a link-local address.
case "$(tcp_probe 169.254.169.254 80)" in
  BLOCKED)   pass "metadata endpoint unreachable from inside a container" ;;
  REACHABLE) fail "metadata endpoint IS REACHABLE from a container -- STOP, do not run any sample" ;;
  *)         fail "metadata probe did not run (container error) -- treat as unverified, do not proceed" ;;
esac

# An arbitrary outbound connection should be redirected to the sinkhole and
# therefore succeed. If it is refused instead, the DNAT rule is not matching,
# and every C2 attempt in a malware batch would be truncated at SYN_SENT --
# losing precisely the TCP features the capture exists to collect.
#
# 203.0.113.0/24 is TEST-NET-3 (RFC 5737), reserved for documentation and
# routed nowhere, so this cannot accidentally contact a real host.
case "$(tcp_probe 203.0.113.45 4444)" in
  REACHABLE) pass "arbitrary outbound TCP reaches the sinkhole (connection established)" ;;
  BLOCKED)   fail "arbitrary outbound TCP did not connect -- DNAT to the sinkhole is not working, TCP features would come out empty" ;;
  *)         fail "sinkhole probe did not run (container error)" ;;
esac

case "$(probe_container 'if timeout 4 getent hosts example.com >/dev/null 2>&1; then echo RESOLVED; else echo NORESOLVE; fi')" in
  NORESOLVE) pass "DNS blocked inside the container" ;;
  RESOLVED)  fail "DNS resolution works inside the container -- it should be blocked" ;;
  *)         fail "DNS probe did not run (container error)" ;;
esac

# --- 4. Monitor sees container installs -------------------------------------
info "4. Monitor visibility into containers  [the critical check]"

: > "$MONITOR_LOG"
"$MONITOR_BIN" -output-dir "$SESSIONS_DIR" >"$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!

monitor_ready=0
for _ in $(seq 1 30); do
  if grep -qE "Tracing|active\." "$MONITOR_LOG" 2>/dev/null; then monitor_ready=1; break; fi
  kill -0 "$MONITOR_PID" 2>/dev/null || break
  sleep 1
done

if [[ $monitor_ready -eq 1 ]]; then
  pass "monitor started and attached its probes"
else
  fail "monitor did not start -- see $MONITOR_LOG"
  echo
  echo "Results: $PASS passed, $FAIL failed"
  exit 1
fi

MARKER=$(mktemp); touch -d "1 second ago" "$MARKER"

info "   installing a real package inside a container"
run_in_container 'cd /work && npm install is-odd' >>"$MONITOR_LOG" 2>&1 || true

info "   settling ${SETTLE_SECS}s"
sleep "$SETTLE_SECS"

SESSION=""
if SESSION=$(wait_for_session "$MARKER"); then
  pass "monitor produced a session for a containerised install: $(basename "$SESSION")"
else
  fail "NO SESSION produced for a containerised install"
  echo
  echo "  This is the blocking failure. The monitor's detector did not see an"
  echo "  npm exec that happened inside a container. Do not run a malware batch:"
  echo "  it would produce empty sessions and the samples cannot be re-run"
  echo "  without provisioning a new VM."
  echo
  echo "  Investigate internal/session/detector.go's exec matching, and check"
  echo "  $MONITOR_LOG for what it did observe."
fi
rm -f "$MARKER"

# --- 5. The session has real content ----------------------------------------
if [[ -n "$SESSION" ]]; then
  info "5. Session content"

  IO_OPS=$(jq -r '.syscalls.io_ops // 0' "$SESSION")
  FILE_OPS=$(jq -r '.syscalls.file_ops // 0' "$SESSION")
  SCHEMA=$(jq -r '.schema_version // "?"' "$SESSION")

  if [[ "$IO_OPS" -gt 100 && "$FILE_OPS" -gt 100 ]]; then
    pass "syscall counts look real (io_ops=$IO_OPS file_ops=$FILE_OPS)"
  else
    fail "syscall counts are implausibly low (io_ops=$IO_OPS file_ops=$FILE_OPS) -- the monitor may be seeing only the container runtime, not the install"
  fi

  if [[ "$SCHEMA" == "1.2.0" ]]; then
    pass "schema version is 1.2.0 (sensitive block present)"
  else
    fail "schema version is $SCHEMA, want 1.2.0 -- rebuild the monitor"
  fi

  if jq -e 'has("sensitive")' "$SESSION" >/dev/null; then
    pass "session contains the sensitive feature block"
  else
    fail "session has no sensitive block -- rebuild the monitor from current source"
  fi
fi

# --- 6. Credential reads reach the feature vector ---------------------------
info "6. Credential-read signal  [second critical check]"

CRED_PKG=$(mktemp -d)
cat > "$CRED_PKG/package.json" <<'JSON'
{
  "name": "harness-credcheck",
  "version": "1.0.0",
  "scripts": { "postinstall": "node postinstall.js" }
}
JSON
cat > "$CRED_PKG/postinstall.js" <<'JS'
// Reads the decoy SSH key the capture image ships. This must show up as
// ssh_private_key_read in the session's sensitive block; if it does not, a
// real credential stealer would be recorded as indistinguishable from benign.
const fs = require('fs');
try { fs.readFileSync('/root/.ssh/id_rsa'); } catch (e) {}
JS

MARKER=$(mktemp); touch -d "1 second ago" "$MARKER"

docker run --rm \
  --label capture-verify \
  --network "$CAPTURE_NET" \
  --dns 127.0.0.1 \
  --volume "$CRED_PKG:/credpkg:ro" \
  --cpus 2 --memory 2g --pids-limit 512 \
  "$IMAGE" bash -lc 'cp -r /credpkg /tmp/credpkg && cd /work && npm install /tmp/credpkg' \
  >>"$MONITOR_LOG" 2>&1 || true

sleep "$SETTLE_SECS"

if CRED_SESSION=$(wait_for_session "$MARKER"); then
  SSH_READ=$(jq -r '.sensitive.ssh_private_key_read // 0' "$CRED_SESSION")
  CRED_READ=$(jq -r '.sensitive.credential_class_read // 0' "$CRED_SESSION")

  if [[ "$SSH_READ" == "1" && "$CRED_READ" == "1" ]]; then
    pass "an SSH key read inside the container reached the feature vector"
  else
    fail "SSH key read did NOT reach the feature vector (ssh_private_key_read=$SSH_READ credential_class_read=$CRED_READ)"
    echo "        Check that the decoy files exist in the image and that"
    echo "        features.ClassifyPath matches the path the container used."
  fi
else
  fail "no session produced for the credential-read check"
fi

rm -f "$MARKER"
rm -rf "$CRED_PKG"

cleanup

# ---------------------------------------------------------------------------
echo
echo "================================================================"
echo " Results: $PASS passed, $FAIL failed"
echo "================================================================"

if [[ $FAIL -gt 0 ]]; then
  echo
  echo " DO NOT run a malware batch until every check passes."
  exit 1
fi

echo
echo " Harness verified. Safe to proceed to the benign corpus."
