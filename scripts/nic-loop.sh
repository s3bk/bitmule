#!/bin/bash
# Send a file from this machine to itself the long way: out of the WiFi card,
# through the router, back in on the Ethernet card.
#
# Two network namespaces each get a virtual interface on top of one physical
# NIC (an ipvlan on the WiFi card, a macvlan on the Ethernet card) with its own
# IP, so the kernel does not recognise the other address as its own and has to
# send the packets onto the wire. Needs a router that bridges WiFi and cable
# (no client isolation).
#
#   sudo scripts/nic-loop.sh up      make the namespaces
#   sudo scripts/nic-loop.sh check   ping across, show which NIC carried it
#   sudo scripts/nic-loop.sh down    remove them
set -eu

WIFI=${WIFI:-wlp2s0}
ETH=${ETH:-enp1s0f0}
PREFIX=${PREFIX:-192.168.100}   # the LAN, a /24
SEND_IP=${SEND_IP:-$PREFIX.6}   # must be unused: the sender (WiFi side)
RECV_IP=${RECV_IP:-$PREFIX.51}  # must be unused: the receiver (cable side)
GATEWAY=${GATEWAY:-$PREFIX.1}

stats() { for i in $WIFI $ETH; do echo "  $i rx=$(cat /sys/class/net/$i/statistics/rx_bytes) tx=$(cat /sys/class/net/$i/statistics/tx_bytes)"; done; }

case "${1:-}" in
up)
    for ip in $SEND_IP $RECV_IP; do
        if arping -q -D -c 2 -w 3 -I $ETH $ip; then :; else echo "$ip is in use, pick another (SEND_IP / RECV_IP)"; exit 1; fi
    done
    ip netns add nic-send
    ip netns add nic-recv
    ip link add link $WIFI name ipw type ipvlan mode l2
    ip link set ipw netns nic-send
    ip link add link $ETH name mve type macvlan mode bridge
    ip link set mve netns nic-recv
    ip -n nic-send addr add $SEND_IP/24 dev ipw
    ip -n nic-send link set ipw up
    ip -n nic-send link set lo up
    ip -n nic-send route add default via $GATEWAY
    ip -n nic-recv addr add $RECV_IP/24 dev mve
    ip -n nic-recv link set mve up
    ip -n nic-recv link set lo up
    ip -n nic-recv route add default via $GATEWAY
    echo "up: sender $SEND_IP (via $WIFI), receiver $RECV_IP (via $ETH)"
    echo
    echo "server (on this host, reachable through the router):"
    echo "  bitmule-server --bind 0.0.0.0:18443 --no-stun      # allow tcp 18443 in the firewall if needed"
    HOSTIP=$(ip -4 -o addr show $ETH | awk '{print $4}' | cut -d/ -f1 | head -1)
    echo "sender:"
    echo "  sudo ip netns exec nic-send sudo -u \$USER bitmule --server http://$HOSTIP:18443 --stun none send --webrtc FILE"
    echo "receiver:"
    echo "  sudo ip netns exec nic-recv sudo -u \$USER bitmule --server http://$HOSTIP:18443 --stun none recv --out OUT '<link>'"
    ;;
check)
    echo "before:"; stats
    ip netns exec nic-send ping -c 3 -W 2 $RECV_IP
    echo "after (WiFi tx and Ethernet rx should have grown by the pings):"; stats
    ;;
down)
    ip netns del nic-send 2>/dev/null || true
    ip netns del nic-recv 2>/dev/null || true
    echo "removed"
    ;;
*)
    sed -n '2,16p' "$0"
    exit 1
    ;;
esac
