#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Source-only nested-tunnel batching regression; no host IP network.
set -euo pipefail
ip netns add wga
ip netns add wgb
cleanup() { ip -n wga link del wg0 2>/dev/null || true; ip -n wgb link del wg0 2>/dev/null || true; ip netns del wga; ip netns del wgb; }
trap cleanup EXIT
ip link set lo up
ip link add wg0 type wireguard
ip link set wg0 netns wga
ip link add wg0 type wireguard
ip link set wg0 netns wgb
ka=$(wg genkey); kb=$(wg genkey)
pa=$(wg pubkey <<< "$ka"); pb=$(wg pubkey <<< "$kb")
ip netns exec wga wg set wg0 private-key <(echo "$ka") listen-port 51820 peer "$pb" allowed-ips 10.70.240.3/32,fd00:70::3/128 endpoint 127.0.0.1:51821
ip netns exec wgb wg set wg0 private-key <(echo "$kb") listen-port 51821 peer "$pa" allowed-ips 10.70.240.2/32,fd00:70::2/128 endpoint 127.0.0.1:51820
unset ka kb
ip -n wga addr add 10.70.240.2/32 dev wg0
ip -n wgb addr add 10.70.240.3/32 dev wg0
ip -n wga -6 addr add fd00:70::2/128 dev wg0 nodad
ip -n wgb -6 addr add fd00:70::3/128 dev wg0 nodad
for ns in wga wgb; do ip -n "$ns" link set wg0 mtu 1370 up; ip -n "$ns" link set lo up; done
ip -n wga route add 10.70.240.3/32 dev wg0
ip -n wgb route add 10.70.240.2/32 dev wg0
ip -n wga -6 route add fd00:70::3/128 dev wg0
ip -n wgb -6 route add fd00:70::2/128 dev wg0
ready() {
 local family=$1 address=$2 deadline=$((SECONDS + 20))
 until ip netns exec wga ping "-$family" -c 1 -W 1 "$address" >/tmp/vxlan-admission.log 2>&1; do
  (( SECONDS < deadline )) || { echo "TUNNEL_ADMISSION_FAILED family=$family address=$address" >&2; exit 1; }
 done
}
for wire_family in 4 6; do
 if [[ $wire_family = 4 ]]; then ea=127.0.0.1:51821; eb=127.0.0.1:51820; else ea='[::1]:51821'; eb='[::1]:51820'; fi
 ip netns exec wga wg set wg0 peer "$pb" endpoint "$ea"
 ip netns exec wgb wg set wg0 peer "$pa" endpoint "$eb"
 ready 4 10.70.240.3
 ready 6 fd00:70::3
 echo "PRIVATE_TUNNEL_READY outer=$wire_family"
 for vxlan_family in 4 6; do
  if [[ $vxlan_family = 4 ]]; then va=10.70.240.2; vb=10.70.240.3; mtu=1320; modes=(udpcsum noudpcsum); else va=fd00:70::2; vb=fd00:70::3; mtu=1300; modes=(default6); fi
  for checksum in "${modes[@]}"; do
   options=(); [[ $checksum = default6 ]] || options=("$checksum")
   ip -n wga link add vx0 type vxlan id 42 local "$va" remote "$vb" dev wg0 dstport 8472 nolearning "${options[@]}"
   ip -n wgb link add vx0 type vxlan id 42 local "$vb" remote "$va" dev wg0 dstport 8472 nolearning "${options[@]}"
   ip -n wga link set vx0 address 02:00:00:00:00:11 mtu "$mtu" up
   ip -n wgb link set vx0 address 02:00:00:00:00:12 mtu "$mtu" up
   ip -n wga addr add 10.123.0.1/24 dev vx0
   ip -n wgb addr add 10.123.0.2/24 dev vx0
   ip -n wga -6 addr add fd00:123::1/64 dev vx0 nodad
   ip -n wgb -6 addr add fd00:123::2/64 dev vx0 nodad
   ip -n wga neigh replace 10.123.0.2 lladdr 02:00:00:00:00:12 nud permanent dev vx0
   ip -n wgb neigh replace 10.123.0.1 lladdr 02:00:00:00:00:11 nud permanent dev vx0
   ip -n wga -6 neigh replace fd00:123::2 lladdr 02:00:00:00:00:12 nud permanent dev vx0
   ip -n wgb -6 neigh replace fd00:123::1 lladdr 02:00:00:00:00:11 nud permanent dev vx0
   ready 4 10.123.0.2
   ready 6 fd00:123::2
   for inner_family in 4 6; do
    if [[ $inner_family = 4 ]]; then bind=10.123.0.2; else bind=fd00:123::2; fi
    for direction in forward reverse; do
     case_id="wg$wire_family-vx$vxlan_family-$checksum-tcp$inner_family-$direction"
     ip netns exec wgb iperf3 -s -1 -B "$bind" >/tmp/vxlan-server.log 2>&1 & server=$!
     deadline=$((SECONDS + 5))
     until [[ $(ss -N wgb -tlH 'sport = 5201') ]]; do (( SECONDS < deadline )) || { echo 'iperf server did not listen' >&2; exit 1; }; done
     flags=(); sender=wga; [[ $direction = forward ]] || { flags=(-R); sender=wgb; }
     echo "BEGIN_LINK $case_id before"; ip -n "$sender" -j -s link show dev wg0; echo END_LINK
     echo "BEGIN_VXLAN $case_id duration=5 streams=4 mtu=$mtu"
     ip netns exec wga iperf3 "-$inner_family" -c "$bind" -t 5 -P 4 -O 1 -J "${flags[@]}"
     wait "$server"
     echo END_VXLAN
     echo "BEGIN_LINK $case_id after"; ip -n "$sender" -j -s link show dev wg0; echo END_LINK
    done
   done
   ip -n wga link del vx0
   ip -n wgb link del vx0
  done
 done
 done
unset pa pb
echo VXLAN_FIXTURE_COMPLETE
