#!/bin/sh
# Loads the netfilter module and checks it drops a blocked source.
# Needs root, and a module built for the running kernel. XG_DEBUG=1 shows
# the raw ping output when a step fails.
#   tests/vm/nf.sh <xdp_guard_nf.ko>
set -eu

module=$1
# shellcheck source=tests/vm/veth.sh
. "$(dirname "$0")/veth.sh"

cleanup() {
	rmmod xdp_guard_nf 2>/dev/null || true
	veth_down
	rm -f "$last_ping"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*"
	debug
	exit 1
}

veth_up

# Without this, a broken setup would pass as a working block.
[ "$(received -c 2 -i 0.2 -W 1)" = 2 ] || fail "pings fail before the module is loaded"

insmod "$module" blocked="$client_ip"
[ "$(received -c 3 -i 0.2 -W 1)" = 0 ] || fail "blocked pings got through"
cat /proc/net/xdp_guard_nf
grep -q '^dropped [1-9]' /proc/net/xdp_guard_nf || fail "dropped counter did not move"
echo "PASS"
