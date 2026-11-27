#!/bin/sh
# Attaches xdp-guard to one end of a veth pair and pings it from a network
# namespace on the other end. Needs root.
#   tests/vm/e2e.sh <xdp-guard binary>
set -eu

guard=$1
pins=/sys/fs/bpf/xdp-guard-e2e
ns=xg-client

cleanup() {
	"$guard" --pin-dir "$pins" detach >/dev/null 2>&1 || true
	ip link del xg0 2>/dev/null || true
	ip netns del "$ns" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*"
	"$guard" --pin-dir "$pins" stats || true
	exit 1
}

counter() {
	"$guard" --pin-dir "$pins" stats | awk -v name="$1" '$1 == name { print $2 }'
}

received() {
	ip netns exec "$ns" ping -n -q "$@" 10.77.0.1 2>/dev/null |
		awk '/received/ { print $4 }'
}

ip netns add "$ns"
ip link add xg0 type veth peer name xg1
ip link set xg1 netns "$ns"
ip addr add 10.77.0.1/24 dev xg0
ip link set xg0 up
ip -n "$ns" addr add 10.77.0.2/24 dev xg1
ip -n "$ns" link set xg1 up

"$guard" --pin-dir "$pins" attach xg0 --mode skb

echo "-- traffic passes"
[ "$(received -c 3 -i 0.2 -W 1)" = 3 ] || fail "pings were dropped with no rules"

echo "-- a blocked source is dropped"
"$guard" --pin-dir "$pins" block 10.77.0.0/30
[ "$(received -c 3 -i 0.2 -W 1)" = 0 ] || fail "blocked pings got through"
[ "$(counter blocked)" -ge 3 ] || fail "blocked counter did not move"
"$guard" --pin-dir "$pins" unblock 10.77.0.0/30
[ "$(received -c 2 -i 0.2 -W 1)" = 2 ] || fail "unblocking did not restore traffic"

echo "-- a flood is held to the limit"
"$guard" --pin-dir "$pins" limit 10 5
got=$(received -c 100 -i 0.01 -W 1)
# 100 pings over about a second: the burst of 5 and about 10 more.
[ "$got" -ge 5 ] && [ "$got" -le 30 ] || fail "$got of 100 pings passed a 10/s limit"
[ "$(counter limited)" -gt 0 ] || fail "limited counter did not move"
"$guard" --pin-dir "$pins" top | grep -q 10.77.0.2 || fail "top does not list the flooder"
"$guard" --pin-dir "$pins" limit off

"$guard" --pin-dir "$pins" stats
"$guard" --pin-dir "$pins" detach
[ ! -e "$pins" ] || fail "detach left pins behind"
echo "PASS"
