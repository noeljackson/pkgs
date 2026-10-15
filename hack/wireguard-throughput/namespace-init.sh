#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
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
ip netns exec wga wg set wg0 private-key <(echo "$ka") listen-port 51820 peer "$pb" allowed-ips 10.70.240.3/32 endpoint 127.0.0.1:51821
ip netns exec wgb wg set wg0 private-key <(echo "$kb") listen-port 51821 peer "$pa" allowed-ips 10.70.240.2/32 endpoint 127.0.0.1:51820
unset ka kb pa pb
ip -n wga addr add 10.70.240.2/32 dev wg0
ip -n wgb addr add 10.70.240.3/32 dev wg0
for ns in wga wgb; do ip -n "$ns" link set wg0 mtu 1370 up; ip -n "$ns" link set lo up; done
ip -n wga route add 10.70.240.3/32 dev wg0
ip -n wgb route add 10.70.240.2/32 dev wg0
ip netns exec wga ping -c 2 -W 2 10.70.240.3
for direction in forward reverse; do
 ip netns exec wgb iperf3 -s -1 -B 10.70.240.3 >/tmp/server.log 2>&1 & server=$!
 deadline=$((SECONDS + 5))
 until [[ $(ss -N wgb -tlH 'sport = 5201') ]]; do
  (( SECONDS < deadline )) || { echo 'iperf server did not listen' >&2; exit 1; }
 done
 flags=(); [[ $direction = forward ]] || flags=(-R)
 echo "BEGIN_SUSTAINED $direction duration=120 streams=4 mtu=1370"
 ip netns exec wga iperf3 -c 10.70.240.3 -t 120 -P 4 -O 3 -J "${flags[@]}"
 wait "$server"
 echo "END_SUSTAINED $direction"
done
