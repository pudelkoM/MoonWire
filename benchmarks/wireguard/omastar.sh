#!/bin/bash

set -e
set -x

apt-get update
apt-get install -y linux-tools-`uname -r`
apt-get install -y software-properties-common ifstat iftop git build-essential cmake linux-headers-`uname -r` lshw libnuma-dev htop fish
add-apt-repository -y ppa:wireguard/wireguard
apt-get update
apt-get install -y wireguard

ip addr flush dev ens3f1
ip addr flush dev ens4f0


# Receiving side

ip a add 10.0.2.1/24 dev ens3f1
ip a add 10.0.1.1/24 dev ens4f0
ip l set mtu 1600 dev ens3f1
ip l set mtu 1600 dev ens4f0
ip l set up dev ens3f1
ip l set up dev ens4f0

ip link add dev wg0 type wireguard
ip l set mtu 1520 dev wg0 # https://lists.zx2c4.com/pipermail/wireguard/2017-December/002201.html
ip a add 192.168.0.1/24 dev wg0
sysctl -w net.ipv4.ip_forward=1

cat << EOF > /tmp/wg.conf
[Interface]
PrivateKey = EBGXRKsOGhdfONoFTP8+NPvTrXS7F1U347BfsJwC0H4=
ListenPort = 1234

[Peer]
PublicKey  = 66tH+Yi9hNpskN6aPVSiCB+suSIf4KBzv8evR1eg1Eg=
EndPoint   = 10.0.1.2:1234
AllowedIPs = 10.0.1.0,10.0.0.0/24,10.0.2.0/24
EOF

wg setconf wg0 /tmp/wg.conf
ip l set up dev wg0
ip r add 10.0.0.0/24 dev wg0

arp -s 10.0.2.2 3C:FD:FE:9E:D7:41


# Sending side

git clone https://github.com/libmoon/libmoon.git
cd libmoon
./build.sh
./setup-hugetlbfs.sh

echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo

echo run "./build/libmoon ../pktgen.lua 0 5 --rate=100"
echo "run \"perf stat -d -a -- sleep 60\""
echo run "ifstat"
echo run "iftop -pnNt"
