#!/usr/bin/env bash
# harden-vm.sh -- lock down a disposable capture VM before any sample runs.
#
# Run this once per VM, as root, BEFORE starting the monitor and BEFORE any
# malicious sample is copied onto the machine. It is idempotent: re-running it
# rebuilds the rules from scratch rather than stacking duplicates.
#
#   sudo bash scripts/capture/harden-vm.sh
#   sudo bash scripts/capture/harden-vm.sh --status    # show current rules
#   sudo bash scripts/capture/harden-vm.sh --teardown  # remove all rules
#
# What it does, and why each part matters:
#
#   1. Blocks 169.254.169.254, the cloud metadata endpoint. On AWS, GCP and
#      Azure any process on the VM can query it and receive the instance's IAM
#      credentials. Malware knows this. Skipping this single step is the most
#      common way a malware-analysis VM turns into a compromised cloud account.
#
#   2. Blocks DNS from the capture network. Containers get the npm registry
#      address injected via --add-host instead (capture.sh does this), so
#      installs still work, while malware cannot resolve its C2 hostname and
#      cannot use DNS queries as an exfiltration channel.
#
#   3. Allows TCP/443 only to the npm registry addresses resolved at hardening
#      time, and redirects every other TCP connection to a local sinkhole.
#      Redirecting rather than dropping is deliberate: the connect() syscall
#      still succeeds and the TCP session still reaches ESTABLISHED, so
#      tcp_state_transitions, tcp_remote_ports and the rest are recorded
#      faithfully. A hard DROP truncates the behaviour at SYN_SENT and loses
#      the very features we are capturing.
#
#   4. Drops all other egress (UDP, ICMP, anything not TCP).
#
# Residual risks this does NOT eliminate, stated plainly:
#   - Malware that connects directly to a hardcoded IP on port 443 reaches the
#     sinkhole, not the attacker, but it still learns it is being contained.
#   - Anything the sample reads on this VM should be assumed exfiltrated to the
#     sinkhole log. That is fine only because the VM holds nothing of value.
#   - This protects the network. It does not sandbox the VM's filesystem. The
#     VM itself is the blast radius, and it must be destroyed after the batch.

set -euo pipefail

METADATA_IP="169.254.169.254"
SINKHOLE_PORT="${SINKHOLE_PORT:-9999}"
CAPTURE_NET="${CAPTURE_NET:-capture-net}"
CAPTURE_SUBNET="${CAPTURE_SUBNET:-172.30.0.0/16}"
CAPTURE_GATEWAY="${CAPTURE_GATEWAY:-172.30.0.1}"
REGISTRY_HOST="${REGISTRY_HOST:-registry.npmjs.org}"

FILTER_CHAIN="CAPTURE_FILTER"
NAT_CHAIN="CAPTURE_NAT"
REGISTRY_IP_FILE="/var/lib/capture-harness/registry-ips"

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

require_root() {
  [[ ${EUID} -eq 0 ]] || die "must run as root (use sudo)"
}

require_tools() {
  local missing=()
  for t in iptables docker getent; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  [[ ${#missing[@]} -eq 0 ]] || die "missing required tools: ${missing[*]}"
}

# ---------------------------------------------------------------------------
# Teardown -- also used at the start of setup so the script is idempotent.
# ---------------------------------------------------------------------------
teardown() {
  info "Removing capture firewall rules"

  # Detach from the built-in chains first; a chain cannot be deleted while
  # anything still jumps to it.
  while iptables -t filter -C DOCKER-USER -j "$FILTER_CHAIN" 2>/dev/null; do
    iptables -t filter -D DOCKER-USER -j "$FILTER_CHAIN"
  done
  while iptables -t filter -C OUTPUT -j "$FILTER_CHAIN" 2>/dev/null; do
    iptables -t filter -D OUTPUT -j "$FILTER_CHAIN"
  done
  while iptables -t nat -C PREROUTING -s "$CAPTURE_SUBNET" -j "$NAT_CHAIN" 2>/dev/null; do
    iptables -t nat -D PREROUTING -s "$CAPTURE_SUBNET" -j "$NAT_CHAIN"
  done

  for spec in "filter $FILTER_CHAIN" "nat $NAT_CHAIN"; do
    local table chain
    table="${spec%% *}"
    chain="${spec##* }"
    if iptables -t "$table" -L "$chain" -n >/dev/null 2>&1; then
      iptables -t "$table" -F "$chain"
      iptables -t "$table" -X "$chain"
    fi
  done

  info "Rules removed. The VM now has unrestricted egress -- do not run samples."
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
status() {
  echo "=== filter/$FILTER_CHAIN ==="
  iptables -t filter -L "$FILTER_CHAIN" -n -v 2>/dev/null || echo "(absent)"
  echo
  echo "=== nat/$NAT_CHAIN ==="
  iptables -t nat -L "$NAT_CHAIN" -n -v 2>/dev/null || echo "(absent)"
  echo
  echo "=== allowed registry addresses ==="
  cat "$REGISTRY_IP_FILE" 2>/dev/null || echo "(none recorded)"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
resolve_registry() {
  info "Resolving $REGISTRY_HOST"

  local ips
  ips=$(getent ahostsv4 "$REGISTRY_HOST" | awk '{print $1}' | sort -u)
  [[ -n "$ips" ]] || die "could not resolve $REGISTRY_HOST -- fix DNS before hardening"

  mkdir -p "$(dirname "$REGISTRY_IP_FILE")"
  printf '%s\n' "$ips" > "$REGISTRY_IP_FILE"

  local count
  count=$(wc -l < "$REGISTRY_IP_FILE")
  info "Allowing $count registry address(es):"
  sed 's/^/      /' "$REGISTRY_IP_FILE"

  # The registry is behind a CDN, so these addresses can change. capture.sh
  # pins one of them into the container's /etc/hosts, which keeps TLS working
  # (the hostname still matches the certificate) but means a rotation mid-batch
  # shows up as installs suddenly failing rather than as silent corruption.
  info "If installs start failing later, re-run this script to re-resolve."
}

create_network() {
  if docker network inspect "$CAPTURE_NET" >/dev/null 2>&1; then
    info "Docker network $CAPTURE_NET already exists"
    return
  fi

  info "Creating Docker network $CAPTURE_NET ($CAPTURE_SUBNET)"
  docker network create \
    --subnet "$CAPTURE_SUBNET" \
    --gateway "$CAPTURE_GATEWAY" \
    "$CAPTURE_NET" >/dev/null
}

build_filter_chain() {
  info "Building filter/$FILTER_CHAIN"

  iptables -t filter -N "$FILTER_CHAIN"

  # 1. Metadata endpoint. First rule, no exceptions, logged so that an attempt
  #    is visible in the capture record rather than silently swallowed.
  iptables -t filter -A "$FILTER_CHAIN" -d "$METADATA_IP" \
    -m limit --limit 5/min -j LOG --log-prefix "CAPTURE-METADATA-BLOCKED: "
  iptables -t filter -A "$FILTER_CHAIN" -d "$METADATA_IP" -j DROP

  # 2. DNS. Containers are given the registry address directly, so nothing
  #    legitimate needs to resolve anything.
  iptables -t filter -A "$FILTER_CHAIN" -s "$CAPTURE_SUBNET" -p udp --dport 53 -j DROP
  iptables -t filter -A "$FILTER_CHAIN" -s "$CAPTURE_SUBNET" -p tcp --dport 53 -j DROP

  # 3. Everything that is not TCP. The sinkhole is a TCP listener, so UDP and
  #    ICMP have nowhere to go and would otherwise leave the VM.
  iptables -t filter -A "$FILTER_CHAIN" -s "$CAPTURE_SUBNET" -p tcp -j RETURN
  iptables -t filter -A "$FILTER_CHAIN" -s "$CAPTURE_SUBNET" -j DROP

  # Attach. DOCKER-USER is Docker's documented hook for user rules and is
  # evaluated before Docker's own FORWARD rules, so container traffic hits it.
  # OUTPUT covers processes on the VM host itself, which is what stops the
  # metadata endpoint being reachable from outside a container too.
  iptables -t filter -I DOCKER-USER 1 -j "$FILTER_CHAIN"
  iptables -t filter -I OUTPUT 1 -j "$FILTER_CHAIN"
}

build_nat_chain() {
  info "Building nat/$NAT_CHAIN (sinkhole on $CAPTURE_GATEWAY:$SINKHOLE_PORT)"

  iptables -t nat -N "$NAT_CHAIN"

  # Registry traffic passes through untouched.
  while read -r ip; do
    [[ -n "$ip" ]] || continue
    iptables -t nat -A "$NAT_CHAIN" -d "$ip" -p tcp --dport 443 -j RETURN
  done < "$REGISTRY_IP_FILE"

  # Everything else is redirected to the sinkhole. The connection succeeds from
  # the sample's point of view, which is what keeps the TCP features real.
  iptables -t nat -A "$NAT_CHAIN" -p tcp \
    -j DNAT --to-destination "$CAPTURE_GATEWAY:$SINKHOLE_PORT"

  iptables -t nat -I PREROUTING 1 -s "$CAPTURE_SUBNET" -j "$NAT_CHAIN"
}

verify() {
  info "Verifying"

  local failures=0

  if iptables -t filter -C "$FILTER_CHAIN" -d "$METADATA_IP" -j DROP 2>/dev/null; then
    echo "      OK   metadata endpoint $METADATA_IP is blocked"
  else
    echo "      FAIL metadata endpoint rule is missing"
    failures=$((failures + 1))
  fi

  # A live check from the host itself. --max-time keeps it quick; a blocked
  # endpoint fails to connect rather than hanging, but the metadata service is
  # link-local and can behave oddly, so the timeout is the safety net.
  if command -v curl >/dev/null 2>&1; then
    if curl --silent --max-time 3 "http://$METADATA_IP/" >/dev/null 2>&1; then
      echo "      FAIL metadata endpoint still answered a live request"
      failures=$((failures + 1))
    else
      echo "      OK   metadata endpoint did not answer a live request"
    fi
  fi

  if ss -lnt 2>/dev/null | grep -q ":$SINKHOLE_PORT "; then
    echo "      OK   sinkhole is listening on port $SINKHOLE_PORT"
  else
    echo "      WARN sinkhole is not listening yet -- start it before capturing:"
    echo "             python3 scripts/capture/sinkhole.py --port $SINKHOLE_PORT"
  fi

  if [[ $failures -gt 0 ]]; then
    die "$failures verification check(s) failed -- do NOT run any sample"
  fi

  info "Hardening complete."
}

main() {
  require_root

  case "${1:-}" in
    --status)
      status
      exit 0
      ;;
    --teardown)
      teardown
      exit 0
      ;;
    "")
      ;;
    *)
      die "unknown argument: $1 (expected --status, --teardown, or nothing)"
      ;;
  esac

  require_tools
  teardown 2>/dev/null || true
  resolve_registry
  create_network
  build_filter_chain
  build_nat_chain
  verify
}

main "$@"
