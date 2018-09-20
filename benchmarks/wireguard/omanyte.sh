#!/bin/bash

set -e
set -x

IF1=enp2s0f0 # 68:05:CA:32:44:D8, 0000:02:00.0, dpdk
IF2=ens1f0 # 68:05:CA:32:44:98, 0000:04:00.0

echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo

apt-get update
apt-get install -y linux-tools-`uname -r`
apt-get install -y software-properties-common ifstat iftop git build-essential cmake linux-headers-`uname -r` lshw libnuma-dev htop fish
add-apt-repository -y ppa:wireguard/wireguard
apt-get update
apt-get install -y wireguard

ip addr flush dev $IF1
ip addr flush dev $IF2


# Receiving side

ip a add 10.1.0.2/24 dev $IF2
ip l set mtu 1600 dev $IF2
ip l set up dev $IF2

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
EndPoint   = 10.1.0.1:1234
AllowedIPs = 10.0.0.0/16,10.1.0.0/16,10.2.0.0/16
EOF

wg setconf wg0 /tmp/wg.conf
ip l set up dev wg0
# ip r add 10.0.0.0/24 dev wg0

# arp -s 10.0.2.2 3C:FD:FE:9E:D7:41


# Sending side

# git clone https://github.com/libmoon/libmoon.git
# cd libmoon
# ./build.sh
# ./setup-hugetlbfs.sh
