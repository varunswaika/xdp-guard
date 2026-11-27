# shellcheck shell=sh
# Sourced by e2e.sh and nf.sh: a veth pair with xg0 on the host and xg1 in
# the network namespace xg-client.
#
# The addresses are from TEST-NET-2 (RFC 5737), which no real network or
# container bridge should be using. If another interface does hold the
# subnet, replies to the client follow that route instead and every ping
# looks dropped, so check before trusting a result.

ns=xg-client
host_ip=198.51.100.1
client_ip=198.51.100.2

veth_up() {
	if ip -o -4 addr show | grep -q " $host_ip/"; then
		echo "FAIL: $host_ip is already on this host:"
		ip -o -4 addr show | grep " $host_ip/"
		exit 1
	fi
	ip netns add "$ns"
	ip link add xg0 type veth peer name xg1
	ip link set xg1 netns "$ns"
	ip addr add "$host_ip/24" dev xg0
	ip link set xg0 up
	ip -n "$ns" addr add "$client_ip/24" dev xg1
	ip -n "$ns" link set xg1 up
	route=$(ip route get "$client_ip")
	case $route in
	*" dev xg0 "*) ;;
	*)
		echo "FAIL: replies to $client_ip would not go out xg0:"
		echo "$route"
		exit 1
		;;
	esac
}

veth_down() {
	ip link del xg0 2>/dev/null || true
	ip netns del "$ns" 2>/dev/null || true
}

# What the last ping printed, kept for XG_DEBUG=1.
last_ping=$(mktemp)

# Pings the host from the namespace and prints how many replies came back.
received() {
	ip netns exec "$ns" ping -n -q "$@" "$host_ip" >"$last_ping" 2>&1 || true
	awk '/received/ { print $4 }' "$last_ping"
}

# With XG_DEBUG=1, shows the raw ping output and the routes on a failure.
debug() {
	[ -n "${XG_DEBUG:-}" ] || return 0
	echo "-- last ping"
	cat "$last_ping"
	echo "-- ip route get $client_ip"
	ip route get "$client_ip" || true
	echo "-- neighbours in $ns"
	ip -n "$ns" neigh || true
}
