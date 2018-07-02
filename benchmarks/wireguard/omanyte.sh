#!/bin/bash

set -e
set -x

apt-get update
apt-get install -y linux-tools-`uname -r`
apt-get install -y software-properties-common ifstat iftop git build-essential cmake linux-headers-`uname -r` lshw libnuma-dev htop fish
add-apt-repository -y ppa:wireguard/wireguard
apt-get update
apt-get install -y wireguard

ip addr flush dev ens1f0
ip addr flush dev enp2s0f0

ip a add 10.0.1.2/24 dev ens1f0
ip a add 10.0.0.2/24 dev enp2s0f0
ip l set up dev ens1f0
ip l set up dev enp2s0f0
ip l set mtu 1600 dev ens1f0
ip l set mtu 1600 dev enp2s0f0
ip l set mtu 1520 dev wg0 # https://lists.zx2c4.com/pipermail/wireguard/2017-December/002201.html
sysctl -w net.ipv4.ip_forward=1

ip link add dev wg0 type wireguard
ip a add 192.168.0.2/24 dev wg0

cat << EOF > /tmp/wg.conf
[Interface]
PrivateKey = sK6HpF8CoQOfNqFGaVzMvn7q14DH4GreXte55v6vmHY=
ListenPort = 1234

[Peer]
PublicKey  = fDd9tw3LEh8sp5KQup4Xs0y9K0SOU9mJ18haDDIixGM=
EndPoint   = 10.0.1.1:1234
AllowedIPs = 10.0.1.1,10.0.0.0/24,10.0.2.0/24,192.168.0.0/24
EOF

wg setconf wg0 /tmp/wg.conf
ip l set up dev wg0
ip r add 10.0.2.0/24 dev wg0

echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo

echo run "ifstat -i enp2s0f0,ens1f0,wg0"