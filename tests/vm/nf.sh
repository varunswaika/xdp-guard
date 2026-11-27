#!/bin/sh
# Loads the netfilter module and checks it drops a blocked source.
# Needs root, and a module built for the running kernel.
#   tests/vm/nf.sh <xdp_guard_nf.ko>
set -eu

module=$1
ns=xg-client

cleanup() {
	rmmod xdp_guard_nf 2>/dev/null || true
	ip link del xg0 2>/dev/null || true
	ip netns del "$ns" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$ns"
ip link add xg0 type veth peer name xg1
ip link set xg1 netns "$ns"
ip addr add 10.77.0.1/24 dev xg0
ip link set xg0 up
ip -n "$ns" addr add 10.77.0.2/24 dev xg1
ip -n "$ns" link set xg1 up

insmod "$module" blocked=10.77.0.2
if ip netns exec "$ns" ping -n -q -c 3 -i 0.2 -W 1 10.77.0.1; then
	echo "FAIL: blocked pings got through"
	exit 1
fi
cat /proc/net/xdp_guard_nf
grep -q '^dropped [1-9]' /proc/net/xdp_guard_nf
echo "PASS"
