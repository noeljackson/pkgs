#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail
read -r cmdline </proc/cmdline
role=client
[[ " $cmdline " != *' wg.role=server '* ]] || role=server
if [[ $role = client ]]; then own=129; peer=130; inner=2; other=3; else own=130; peer=129; inner=3; other=2; fi
# Publicly known synthetic fixture identities; never used outside this VM pair.
ka=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
kb=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
if [[ $role = client ]]; then key=$ka; pub=$(wg pubkey <<< "$kb"); else key=$kb; pub=$(wg pubkey <<< "$ka"); fi
ip link set lo up
ip addr add "198.18.0.$own/24" dev eth0
ip link set eth0 mtu 1500 up
ip -6 addr add "fd00:4714::$own/64" dev eth0
ip link add wg0 type wireguard
wg set wg0 private-key <(echo "$key") listen-port 51820 peer "$pub" allowed-ips "10.70.240.$other/32" endpoint "198.18.0.$peer:51820"
[[ $(wg show wg0 public-key) = $(wg pubkey <<< "$key") ]]
unset ka kb key pub
ip addr add "10.70.240.$inner/32" dev wg0
ip link set wg0 mtu 1370 up
ip route add "10.70.240.$other/32" dev wg0
# Count outer UDP on both mandatory policy paths.
iptables -t mangle -A PREROUTING -p udp --dport 51820
iptables -A INPUT -p udp --dport 51820
if [[ $role = server ]]; then
 for direction in raw-forward raw-reverse; do iperf3 -s -1 -B 198.18.0.130; done
 for direction in forward reverse forward6 reverse6; do iperf3 -s -1 -B 10.70.240.3; done
else
 ping -c 3 -W 2 198.18.0.130
 ping -c 40 -f -W 2 10.70.240.3
 # Exercise selection of a replacement when a reused worker CPU goes offline.
 online=( /sys/devices/system/cpu/cpu[1-9]/online )
 [[ -f ${online[0]} ]]
 for cpu in "${online[@]}"; do echo 0 >"$cpu"; done
 ping -c 2 -W 2 10.70.240.3
 for cpu in "${online[@]}"; do echo 1 >"$cpu"; done
 echo HOTPLUG_PASS
 for direction in raw-forward raw-reverse; do
  flags=(); [[ $direction = raw-forward ]] || flags=(-R)
  echo "BEGIN_WIRE $direction duration=20 streams=4 mtu=1500"
  iperf3 -c 198.18.0.130 -t 20 -P 4 -O 3 -J "${flags[@]}"
  echo "END_WIRE $direction"
 done
 for direction in forward reverse forward6 reverse6; do
  flags=(); [[ $direction != reverse* ]] || flags=(-R)
  duration=120
  if [[ $direction = *6 ]]; then
   wg set wg0 peer "$(wg show wg0 peers)" endpoint '[fd00:4714::130]:51820'
   duration=10
  fi
  echo "BEGIN_WIRE $direction duration=$duration streams=4 mtu=1370"
  iperf3 -c 10.70.240.3 -t "$duration" -P 4 -O 3 -J "${flags[@]}"
  echo "END_WIRE $direction"
 done
fi
for path in 'mangle PREROUTING' 'filter INPUT'; do
 read -r table chain <<< "$path"
 rules=$(iptables -t "$table" -nvxL "$chain")
 printf '%s\n' "$rules"
 found=0
 while read -r packets bytes protocol rest; do
  if [[ $protocol = udp ]]; then (( packets > 0 && bytes > 0 )); found=1; fi
 done <<< "$rules"
 (( found == 1 ))
done
echo POLICY_PASS
ip -s link show eth0
ip -s link show wg0
wg show wg0 transfer
