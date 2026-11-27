#!/bin/sh
# Attaches xdp-guard to one end of a veth pair and pings it from a network
# namespace on the other end. Needs root. XG_DEBUG=1 shows the raw ping
# output when a step fails.
#   tests/vm/e2e.sh <xdp-guard binary>
set -eu

guard=$1
pins=/sys/fs/bpf/xdp-guard-e2e
# shellcheck source=tests/vm/veth.sh
. "$(dirname "$0")/veth.sh"

cleanup() {
	"$guard" --pin-dir "$pins" detach >/dev/null 2>&1 || true
	veth_down
	rm -f "$last_ping"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*"
	"$guard" --pin-dir "$pins" stats || true
	debug
	exit 1
}

counter() {
	"$guard" --pin-dir "$pins" stats | awk -v name="$1" '$1 == name { print $2 }'
}

veth_up
"$guard" --pin-dir "$pins" attach xg0 --mode skb

echo "-- traffic passes"
[ "$(received -c 3 -i 0.2 -W 1)" = 3 ] || fail "pings were dropped with no rules"

echo "-- a blocked source is dropped"
"$guard" --pin-dir "$pins" block "$client_ip/30"
[ "$(received -c 3 -i 0.2 -W 1)" = 0 ] || fail "blocked pings got through"
[ "$(counter blocked)" -ge 3 ] || fail "blocked counter did not move"
"$guard" --pin-dir "$pins" unblock "$client_ip/30"
[ "$(received -c 2 -i 0.2 -W 1)" = 2 ] || fail "unblocking did not restore traffic"

echo "-- a flood is held to the limit"
"$guard" --pin-dir "$pins" limit 10 5
got=$(received -c 100 -i 0.01 -W 1)
# 100 pings over about a second: the burst of 5 and about 10 more.
[ "$got" -ge 5 ] && [ "$got" -le 30 ] || fail "$got of 100 pings passed a 10/s limit"
[ "$(counter limited)" -gt 0 ] || fail "limited counter did not move"
"$guard" --pin-dir "$pins" top | grep -q "$client_ip" || fail "top does not list the flooder"
"$guard" --pin-dir "$pins" limit off

"$guard" --pin-dir "$pins" stats
"$guard" --pin-dir "$pins" detach
[ ! -e "$pins" ] || fail "detach left pins behind"
echo "PASS"
