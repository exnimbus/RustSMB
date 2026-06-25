#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-print}"
iface="${IFACE:-}"
host="${HOST:-}"
port="${PORT:-445}"
proto="${PROTO:-tcp}"
rtt_ms="${RTT_MS:-80}"
loss_pct="${LOSS_PCT:-0}"
bandwidth_mbps="${BANDWIDTH_MBPS:-0}"
pipe_id="${PIPE:-4450}"
anchor="${ANCHOR:-gosmb-wanem}"

usage() {
  cat <<'EOF'
Usage:
  HOST=192.0.2.10 PORT=445 PROTO=tcp RTT_MS=80 LOSS_PCT=0.1 BANDWIDTH_MBPS=1000 tools/wanem.sh print
  HOST=192.0.2.10 PORT=445 PROTO=tcp RTT_MS=80 LOSS_PCT=0.1 BANDWIDTH_MBPS=1000 tools/wanem.sh apply
  tools/wanem.sh clear

Environment:
  HOST       Peer host to match on macOS pf/dnctl. Required for macOS apply/print.
  PORT       Port to match on macOS. Default: 445.
  PROTO      Protocol to match on macOS: tcp or udp. Default: tcp.
  IFACE      Linux interface for tc netem. Required on Linux apply/print.
  RTT_MS     Approximate round-trip latency to emulate. Default: 80.
  LOSS_PCT   Packet loss percentage for OS netem/dummynet. Default: 0.
  BANDWIDTH_MBPS  Optional bandwidth cap in megabits/sec. 0 disables. Default: 0.
  PIPE       macOS dnctl pipe id. Default: 4450.
  ANCHOR     macOS pf anchor name. Default: gosmb-wanem.

Notes:
  macOS mode targets PROTO traffic to/from HOST:PORT with pf + dnctl.
  Linux mode applies netem to the whole IFACE root qdisc.
  With sudo on macOS, preserve variables with sudo env HOST=... PORT=... tools/wanem.sh apply.
EOF
}

need_integer() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|*[!0-9]*)
      echo "$name must be an integer, got '$value'" >&2
      exit 2
      ;;
  esac
}

need_range() {
  local name="$1"
  local value="$2"
  local min="$3"
  local max="$4"
  local n=$((10#$value))
  if (( n < min || n > max )); then
    echo "$name must be between $min and $max, got '$value'" >&2
    exit 2
  fi
}

need_loss_percent() {
  local value="$1"
  awk -v v="$value" '
    BEGIN {
      if (v !~ /^[0-9]+([.][0-9]+)?$/ || v < 0 || v > 100) {
        printf "LOSS_PCT must be a number between 0 and 100, got '\''%s'\''\n", v > "/dev/stderr"
        exit 2
      }
    }'
}

need_proto() {
  case "$1" in
    tcp|udp) ;;
    *) echo "PROTO must be tcp or udp, got '$1'" >&2; exit 2 ;;
  esac
}

need_integer RTT_MS "$rtt_ms"
need_integer PORT "$port"
need_integer PIPE "$pipe_id"
need_integer BANDWIDTH_MBPS "$bandwidth_mbps"
need_range PORT "$port" 1 65535
need_range PIPE "$pipe_id" 1 65535
need_loss_percent "$loss_pct"
need_proto "$proto"

oneway_ms=$(( (rtt_ms + 1) / 2 ))
loss_plr="$(awk -v p="$loss_pct" 'BEGIN { printf "%.6f", p / 100 }')"
bandwidth_darwin=()
bandwidth_linux=()
bandwidth_darwin_print=""
bandwidth_linux_print=""
if (( 10#$bandwidth_mbps > 0 )); then
  bandwidth_darwin=(bw "${bandwidth_mbps}Mbit/s")
  bandwidth_linux=(rate "${bandwidth_mbps}mbit")
  bandwidth_darwin_print=" bw ${bandwidth_mbps}Mbit/s"
  bandwidth_linux_print=" rate ${bandwidth_mbps}mbit"
fi

os="$(uname -s)"

print_darwin() {
  if [[ -z "$host" ]]; then
    echo "HOST is required on macOS" >&2
    exit 2
  fi
  cat <<EOF
sudo dnctl -q pipe $pipe_id delete || true
sudo dnctl pipe $pipe_id config delay ${oneway_ms}ms plr $loss_plr$bandwidth_darwin_print
printf '%s\n' \\
  'dummynet out quick proto $proto from any to $host port $port pipe $pipe_id' \\
  'dummynet in quick proto $proto from $host port $port to any pipe $pipe_id' \\
  | sudo pfctl -a $anchor -f -
sudo pfctl -E
EOF
}

apply_darwin() {
  if [[ -z "$host" ]]; then
    echo "HOST is required on macOS" >&2
    exit 2
  fi
  sudo dnctl -q pipe "$pipe_id" delete || true
  sudo dnctl pipe "$pipe_id" config delay "${oneway_ms}ms" plr "$loss_plr" "${bandwidth_darwin[@]}"
  printf '%s\n' \
    "dummynet out quick proto $proto from any to $host port $port pipe $pipe_id" \
    "dummynet in quick proto $proto from $host port $port to any pipe $pipe_id" \
    | sudo pfctl -a "$anchor" -f -
  sudo pfctl -E >/dev/null || true
}

clear_darwin() {
  printf '' | sudo pfctl -a "$anchor" -f - || true
  sudo dnctl -q pipe "$pipe_id" delete || true
}

print_linux() {
  if [[ -z "$iface" ]]; then
    echo "IFACE is required on Linux" >&2
    exit 2
  fi
  cat <<EOF
sudo tc qdisc replace dev $iface root netem delay ${oneway_ms}ms loss ${loss_pct}%$bandwidth_linux_print
EOF
}

apply_linux() {
  if [[ -z "$iface" ]]; then
    echo "IFACE is required on Linux" >&2
    exit 2
  fi
  sudo tc qdisc replace dev "$iface" root netem delay "${oneway_ms}ms" loss "${loss_pct}%" "${bandwidth_linux[@]}"
}

clear_linux() {
  if [[ -z "$iface" ]]; then
    echo "IFACE is required on Linux" >&2
    exit 2
  fi
  sudo tc qdisc del dev "$iface" root || true
}

case "$cmd" in
  -h|--help|help)
    usage
    ;;
  print)
    case "$os" in
      Darwin) print_darwin ;;
      Linux) print_linux ;;
      *) echo "unsupported OS: $os" >&2; exit 2 ;;
    esac
    ;;
  apply)
    case "$os" in
      Darwin) apply_darwin ;;
      Linux) apply_linux ;;
      *) echo "unsupported OS: $os" >&2; exit 2 ;;
    esac
    ;;
  clear)
    case "$os" in
      Darwin) clear_darwin ;;
      Linux) clear_linux ;;
      *) echo "unsupported OS: $os" >&2; exit 2 ;;
    esac
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
