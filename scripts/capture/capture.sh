#!/usr/bin/env bash
# capture.sh -- run npm installs one per fresh container and collect the
# eBPF monitor's session JSON for each.
#
#   # benign batch from a package list
#   sudo bash scripts/capture/capture.sh \
#     --list scripts/capture/packages-benign.txt --label 0 --out captures/benign
#
#   # a single package
#   sudo bash scripts/capture/capture.sh --package lodash --label 0 --out captures/benign
#
#   # malware batch: local tarballs in a directory, installed by bare filename
#   sudo bash scripts/capture/capture.sh \
#     --tarball-dir /root/samples/batch-01 --label 1 --out captures/malware
#
# Safety gates. The script refuses to start unless harden-vm.sh has been run
# and the sinkhole is listening. Do not add a flag to skip them.
#
# Read scripts/capture/README.md before the first malware batch.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

MONITOR_BIN="${MONITOR_BIN:-$PROJECT_ROOT/npm-ebpf-monitor}"
SESSIONS_DIR="${SESSIONS_DIR:-/var/lib/capture-harness/sessions}"
MONITOR_LOG="${MONITOR_LOG:-/var/log/capture/monitor.log}"

IMAGE="${IMAGE:-capture-harness:node20}"
CAPTURE_NET="${CAPTURE_NET:-capture-net}"
SINKHOLE_PORT="${SINKHOLE_PORT:-9999}"
FILTER_CHAIN="CAPTURE_FILTER"
REGISTRY_HOST="${REGISTRY_HOST:-registry.npmjs.org}"
REGISTRY_IP_FILE="/var/lib/capture-harness/registry-ips"

# Seconds to let the install's events drain out of the ring buffers before the
# session is expected to be complete. The monitor's own session-timeout
# defaults to 120s; this is the quiet period after npm itself exits.
SETTLE_SECS="${SETTLE_SECS:-20}"
# Seconds to poll for the session JSON after settling.
JSON_WAIT_SECS="${JSON_WAIT_SECS:-45}"
# Hard cap on a single install. Malware that hangs must not stall the batch.
INSTALL_TIMEOUT_SECS="${INSTALL_TIMEOUT_SECS:-180}"
# Container resource caps. A cryptominer sample should not be able to peg the
# VM or exhaust its memory and take the monitor down with it.
CONTAINER_CPUS="${CONTAINER_CPUS:-2}"
CONTAINER_MEMORY="${CONTAINER_MEMORY:-2g}"
CONTAINER_PIDS="${CONTAINER_PIDS:-512}"

MODE=""
TARGET=""
LABEL=""
OUT_DIR=""

MONITOR_PID=""

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "WARN: $*" >&2; }

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --list)        MODE="list";       TARGET="$2"; shift 2 ;;
      --package)     MODE="package";    TARGET="$2"; shift 2 ;;
      --tarball-dir) MODE="tarballdir"; TARGET="$2"; shift 2 ;;
      --label)       LABEL="$2";        shift 2 ;;
      --out)         OUT_DIR="$2";      shift 2 ;;
      -h|--help)     usage ;;
      *)             die "unknown argument: $1" ;;
    esac
  done

  [[ -n "$MODE" ]]    || die "one of --list, --package or --tarball-dir is required"
  [[ -n "$OUT_DIR" ]] || die "--out is required"

  # The label is required rather than defaulted. A defaulted label is what put
  # genuinely malicious sessions into the training set marked benign
  # (AUDIT.md C4), and once written the mistake is invisible.
  case "$LABEL" in
    0|1) ;;
    "")  die "--label is required (0 = benign, 1 = malicious)" ;;
    *)   die "--label must be 0 or 1, got: $LABEL" ;;
  esac
}

# ---------------------------------------------------------------------------
# Safety gates
# ---------------------------------------------------------------------------
preflight() {
  [[ ${EUID} -eq 0 ]] || die "must run as root (the monitor needs CAP_BPF and Docker needs root)"

  for t in docker iptables jq timeout ss; do
    command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"
  done

  [[ -x "$MONITOR_BIN" ]] || die "monitor binary not found or not executable: $MONITOR_BIN (run 'make build')"

  # Gate 1: the firewall must be up.
  iptables -t filter -L "$FILTER_CHAIN" -n >/dev/null 2>&1 \
    || die "firewall chain $FILTER_CHAIN is absent -- run 'sudo bash $SCRIPT_DIR/harden-vm.sh' first"

  iptables -t filter -C "$FILTER_CHAIN" -d 169.254.169.254 -j DROP 2>/dev/null \
    || die "the cloud metadata endpoint is NOT blocked -- re-run harden-vm.sh and do not proceed"

  # Gate 2: the sinkhole must be listening, or every redirected C2 connection
  # gets a refusal instead of an ESTABLISHED session and the TCP features come
  # out empty -- the failure mode that would quietly ruin a whole malware batch.
  ss -lnt | grep -q ":$SINKHOLE_PORT " \
    || die "no sinkhole listening on port $SINKHOLE_PORT -- start it with: python3 $SCRIPT_DIR/sinkhole.py --port $SINKHOLE_PORT --log /var/log/capture/sinkhole.jsonl"

  # Gate 3: the capture network must exist.
  docker network inspect "$CAPTURE_NET" >/dev/null 2>&1 \
    || die "docker network $CAPTURE_NET is absent -- run harden-vm.sh first"

  [[ -s "$REGISTRY_IP_FILE" ]] \
    || die "no resolved registry addresses at $REGISTRY_IP_FILE -- run harden-vm.sh first"

  mkdir -p "$SESSIONS_DIR" "$OUT_DIR" "$(dirname "$MONITOR_LOG")"

  info "Safety gates passed"
}

build_image() {
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    info "Container image $IMAGE already built"
    return
  fi
  info "Building container image $IMAGE"
  docker build --quiet --tag "$IMAGE" "$SCRIPT_DIR" >/dev/null
}

# ---------------------------------------------------------------------------
# Monitor lifecycle
# ---------------------------------------------------------------------------
start_monitor() {
  info "Starting eBPF monitor"
  : > "$MONITOR_LOG"

  "$MONITOR_BIN" -output-dir "$SESSIONS_DIR" >"$MONITOR_LOG" 2>&1 &
  MONITOR_PID=$!

  for _ in $(seq 1 30); do
    if grep -qE "Tracing|active\." "$MONITOR_LOG" 2>/dev/null; then
      info "Monitor ready (pid $MONITOR_PID)"
      return 0
    fi
    if ! kill -0 "$MONITOR_PID" 2>/dev/null; then
      cat "$MONITOR_LOG" >&2
      die "monitor exited during startup"
    fi
    sleep 1
  done

  cat "$MONITOR_LOG" >&2
  die "monitor did not report readiness within 30s"
}

stop_monitor() {
  [[ -n "$MONITOR_PID" ]] || return 0
  kill -0 "$MONITOR_PID" 2>/dev/null || return 0

  info "Stopping monitor"
  kill -TERM "$MONITOR_PID" 2>/dev/null || true
  wait "$MONITOR_PID" 2>/dev/null || true
  MONITOR_PID=""
}

cleanup() {
  stop_monitor
  # Any container still alive at this point is a sample that ignored the
  # timeout. Kill it rather than leaving malware running on the VM.
  docker ps --quiet --filter "label=capture-harness" | while read -r cid; do
    [[ -n "$cid" ]] && docker kill "$cid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

# run_install <install-arg> [host-tarball-dir]
#
# Starts a fresh container, runs one npm install, and tears the container down.
# Returns the container's exit status; a non-zero status is recorded but not
# treated as fatal, because a failed install is itself a valid observation
# (and a fair amount of real malware breaks the install it is attached to).
run_install() {
  local install_arg="$1"
  local mount_dir="${2:-}"

  local -a mount_args=()
  if [[ -n "$mount_dir" ]]; then
    # Read-only: the sample must not be able to modify the sample corpus.
    mount_args=(--volume "$mount_dir:/samples:ro")
  fi

  local registry_ip
  registry_ip=$(head -n 1 "$REGISTRY_IP_FILE")

  timeout --signal=KILL "$INSTALL_TIMEOUT_SECS" \
    docker run --rm \
      --label capture-harness \
      --network "$CAPTURE_NET" \
      --add-host "$REGISTRY_HOST:$registry_ip" \
      --dns 127.0.0.1 \
      --cpus "$CONTAINER_CPUS" \
      --memory "$CONTAINER_MEMORY" \
      --pids-limit "$CONTAINER_PIDS" \
      "${mount_args[@]}" \
      "$IMAGE" \
      bash -lc "set -x; cd /work && ${install_arg}" \
    >>"$MONITOR_LOG" 2>&1
}

# wait_for_session <since-marker-file>
#
# Polls the sessions directory for a JSON file newer than the marker and echoes
# its path. Matching on mtime rather than on the package name is deliberate:
# the monitor derives the package name from the install argument, which for a
# tarball is the filename and for a scoped package contains characters the
# writer sanitises, so name matching is unreliable in exactly the cases that
# matter most.
wait_for_session() {
  local marker="$1"
  local elapsed=0

  while [[ $elapsed -lt $JSON_WAIT_SECS ]]; do
    local found
    found=$(find "$SESSIONS_DIR" -maxdepth 1 -name '*.json' -newer "$marker" -print -quit 2>/dev/null || true)
    if [[ -n "$found" ]]; then
      echo "$found"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  return 1
}

# capture_one <display-name> <install-arg> [host-tarball-dir]
capture_one() {
  local name="$1"
  local install_arg="$2"
  local mount_dir="${3:-}"

  echo
  info "[$CAPTURE_INDEX/$CAPTURE_TOTAL] $name"

  local marker
  marker=$(mktemp)
  # Back-date the marker by a second so a session written in the same second
  # the install starts is still seen as newer.
  touch -d "1 second ago" "$marker"

  local install_status=0
  run_install "$install_arg" "$mount_dir" || install_status=$?
  if [[ $install_status -ne 0 ]]; then
    warn "install exited $install_status (recorded; not treated as a capture failure)"
  fi

  info "    settling ${SETTLE_SECS}s"
  sleep "$SETTLE_SECS"

  local session_file
  if ! session_file=$(wait_for_session "$marker"); then
    rm -f "$marker"
    warn "no session JSON produced for $name after ${JSON_WAIT_SECS}s"
    record_manifest "$name" "" "$install_status" "NO_SESSION"
    FAILED=$((FAILED + 1))
    return 0
  fi
  rm -f "$marker"

  # Stamp the externally-known ground truth into the record. For these captures
  # the label comes from which corpus the sample was drawn from, not from a
  # filename rule and not from the verdict engine -- using verdict output would
  # be circular, since ml_analysis/feature_analysis.py derives labels from it.
  local dest="$OUT_DIR/$(basename "$session_file")"
  jq --argjson label "$LABEL" \
     --arg source "$name" \
     '.label = $label | .capture_source = $source' \
     "$session_file" > "$dest" \
    || { warn "failed to write labelled session for $name"; FAILED=$((FAILED + 1)); return 0; }

  local verdict_level
  verdict_level=$(jq -r '.verdict.level // "none"' "$dest")
  info "    session: $(basename "$dest")  verdict=$verdict_level"

  record_manifest "$name" "$(basename "$dest")" "$install_status" "OK"
  CAPTURED=$((CAPTURED + 1))
}

record_manifest() {
  printf '%s,%s,%s,%s,%s\n' \
    "$1" "$LABEL" "$2" "$3" "$4" >> "$MANIFEST"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  parse_args "$@"
  preflight
  build_image

  MANIFEST="$OUT_DIR/manifest.csv"
  if [[ ! -f "$MANIFEST" ]]; then
    echo "package,label,session_file,install_exit,status" > "$MANIFEST"
  fi

  # Build the work list.
  local -a names=() install_args=()
  local mount_dir=""

  case "$MODE" in
    package)
      names+=("$TARGET")
      install_args+=("npm install $(printf '%q' "$TARGET")")
      ;;
    list)
      [[ -f "$TARGET" ]] || die "package list not found: $TARGET"
      while read -r line; do
        line="${line%%#*}"
        line="$(echo "$line" | xargs)"
        [[ -n "$line" ]] || continue
        names+=("$line")
        install_args+=("npm install $(printf '%q' "$line")")
      done < "$TARGET"
      ;;
    tarballdir)
      [[ -d "$TARGET" ]] || die "tarball directory not found: $TARGET"
      mount_dir="$TARGET"
      while IFS= read -r f; do
        local base
        base=$(basename "$f")
        names+=("$base")
        # Copy into the working directory and install by bare filename. An
        # absolute path would be recorded verbatim as the package name by
        # detector.go's parseInstallTarget, and the slashes then get collapsed
        # by the filename sanitiser, making the session hard to trace back to
        # its sample.
        install_args+=("cp /samples/$(printf '%q' "$base") . && npm install ./$(printf '%q' "$base")")
      done < <(find "$TARGET" -maxdepth 1 -type f \( -name '*.tgz' -o -name '*.tar.gz' \) | sort)
      ;;
  esac

  CAPTURE_TOTAL=${#names[@]}
  [[ $CAPTURE_TOTAL -gt 0 ]] || die "nothing to capture"

  info "Capturing $CAPTURE_TOTAL sample(s), label=$LABEL, out=$OUT_DIR"
  if [[ "$LABEL" == "1" ]]; then
    echo
    echo "  !! This batch is labelled MALICIOUS. Confirm before continuing:"
    echo "     - this VM is disposable and holds nothing worth stealing"
    echo "     - it will be destroyed after this batch, not reused"
    echo "     - a billing alarm is set"
    echo
    read -r -p "  Type 'yes' to proceed: " confirm
    [[ "$confirm" == "yes" ]] || die "aborted by operator"
  fi

  start_monitor

  CAPTURED=0
  FAILED=0
  CAPTURE_INDEX=0

  local i
  for i in "${!names[@]}"; do
    CAPTURE_INDEX=$((i + 1))
    capture_one "${names[$i]}" "${install_args[$i]}" "$mount_dir"
  done

  stop_monitor

  echo
  info "Done. captured=$CAPTURED failed=$FAILED of $CAPTURE_TOTAL"
  info "Manifest: $MANIFEST"

  if [[ "$LABEL" == "1" ]]; then
    echo
    echo "  Next: copy ONLY $OUT_DIR off this VM, then destroy the VM."
    echo "  Never copy back a tarball, a node_modules directory, or anything executable."
  fi

  [[ $FAILED -eq 0 ]] || exit 1
}

main "$@"
