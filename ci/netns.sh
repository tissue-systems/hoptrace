#!/bin/sh
# Builds a three-namespace path on Linux, so the error-queue code runs
# against a real router instead of loopback:
#
#   hop-client  192.0.2.2     2001:db8:1::2
#        |
#   hop-router  192.0.2.1     2001:db8:1::1     (forwards; 203.0.113.0/24
#               198.51.100.1  2001:db8:2::1      and 2001:db8:3::/64 unreachable)
#        |
#   hop-target  198.51.100.2  2001:db8:2::2
#
# Usage: sudo ci/netns.sh up | down
# Then run tests/netns.rs inside hop-client, as an ordinary user:
#   sudo ip netns exec hop-client sudo -u "$USER" HOPTRACE_NETNS=1 \
#       target/debug/deps/netns-<hash> --ignored
set -eu

# Linux routers send at most one Unreachable a second per destination, and
# that limit (net.ipv4.route.error_cost) is host-wide rather than per
# namespace. `up` lifts it for the run and `down` puts the old value back.
saved=/run/hoptrace-netns-error-cost

down() {
    for ns in hop-client hop-router hop-target; do
        ip netns del "$ns" 2>/dev/null || true
    done
    if [ -f "$saved" ]; then
        sysctl -qw net.ipv4.route.error_cost="$(cat "$saved")"
        rm -f "$saved"
    fi
}

# neigh NS DEV PEER_NS PEER_DEV V4 V6: in NS, V4 and V6 are on PEER_DEV's MAC.
neigh() {
    mac=$(ip -n "$3" -br link show "$4" | awk '{print $3}')
    ip -n "$1" neigh replace "$5" lladdr "$mac" dev "$2" nud permanent
    ip -n "$1" -6 neigh replace "$6" lladdr "$mac" dev "$2" nud permanent
}

up() {
    down
    for ns in hop-client hop-router hop-target; do
        ip netns add "$ns"
        ip -n "$ns" link set lo up
    done
    ip link add c0 netns hop-client type veth peer name r0 netns hop-router
    ip link add r1 netns hop-router type veth peer name t0 netns hop-target

    ip -n hop-client addr add 192.0.2.2/24 dev c0
    ip -n hop-client addr add 2001:db8:1::2/64 dev c0 nodad
    ip -n hop-router addr add 192.0.2.1/24 dev r0
    ip -n hop-router addr add 2001:db8:1::1/64 dev r0 nodad
    ip -n hop-router addr add 198.51.100.1/24 dev r1
    ip -n hop-router addr add 2001:db8:2::1/64 dev r1 nodad
    ip -n hop-target addr add 198.51.100.2/24 dev t0
    ip -n hop-target addr add 2001:db8:2::2/64 dev t0 nodad
    ip -n hop-client link set c0 up
    ip -n hop-router link set r0 up
    ip -n hop-router link set r1 up
    ip -n hop-target link set t0 up

    ip -n hop-client route add default via 192.0.2.1
    ip -n hop-client -6 route add default via 2001:db8:1::1
    ip -n hop-target route add default via 198.51.100.1
    ip -n hop-target -6 route add default via 2001:db8:2::1
    ip -n hop-router route add unreachable 203.0.113.0/24
    ip -n hop-router -6 route add unreachable 2001:db8:3::/64

    # Static neighbors, so no trace waits on ARP or neighbor discovery
    # the first time a namespace speaks.
    neigh hop-client c0 hop-router r0 192.0.2.1 2001:db8:1::1
    neigh hop-router r0 hop-client c0 192.0.2.2 2001:db8:1::2
    neigh hop-router r1 hop-target t0 198.51.100.2 2001:db8:2::2
    neigh hop-target t0 hop-router r1 198.51.100.1 2001:db8:2::1

    # Answers come back 0 to 10 ms late, so they land while a pass is still
    # sending, as they do on a real path.
    ip netns exec hop-router tc qdisc add dev r0 root netem delay 5ms 5ms

    ip netns exec hop-router sysctl -qw net.ipv4.ip_forward=1
    ip netns exec hop-router sysctl -qw net.ipv6.conf.all.forwarding=1
    # The tests check the plumbing, not the kernel's ICMP rate limits.
    ip netns exec hop-router sysctl -qw net.ipv4.icmp_ratelimit=0
    ip netns exec hop-router sysctl -qw net.ipv6.icmp.ratelimit=0
    # Those two are per destination. Every ICMP error also draws on one shared
    # bucket, and its burst is randomized, so four tracers at once through the
    # router sometimes lost a Time Exceeded to it.
    ip netns exec hop-router sysctl -qw net.ipv4.icmp_msgs_per_sec=100000
    ip netns exec hop-router sysctl -qw net.ipv4.icmp_msgs_burst=10000
    sysctl -n net.ipv4.route.error_cost >"$saved"
    sysctl -qw net.ipv4.route.error_cost=0
    ip netns exec hop-client sysctl -qw net.ipv4.ping_group_range="0 2147483647"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
