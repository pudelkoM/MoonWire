#!/bin/bash

set -e
set -x

IF1=ens3f0 # 3C:FD:FE:9E:D6:B8, 0000:03:00.0
IF2=ens4f0 # 3C:FD:FE:9E:D7:40, 0000:83:00.0

echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo

apt-get update
apt-get install -y linux-tools-`uname -r`
apt-get install -y software-properties-common ifstat iftop git build-essential cmake linux-headers-`uname -r` lshw libnuma-dev htop fish
add-apt-repository -y ppa:wireguard/wireguard
apt-get update
apt-get install -y wireguard

ip addr flush dev $IF1
ip addr flush dev $IF2

ip a add 10.0.0.1/16 dev $IF1
ip a add 10.1.0.1/24 dev $IF2
ip l set mtu 1600 dev $IF1
ip l set mtu 1600 dev $IF2
ip l set up dev $IF1
ip l set up dev $IF2
sysctl -w net.ipv4.ip_forward=1

ip link add dev wg0 type wireguard
ip l set mtu 1520 dev wg0 # https://lists.zx2c4.com/pipermail/wireguard/2017-December/002201.html
ip a add 192.168.0.2/24 dev wg0

cat << EOF > /tmp/wg.conf
[Interface]
PrivateKey = sK6HpF8CoQOfNqFGaVzMvn7q14DH4GreXte55v6vmHY=
ListenPort = 1234

[Peer]
PublicKey  = fDd9tw3LEh8sp5KQup4Xs0y9K0SOU9mJ18haDDIixGM=
EndPoint   = 10.1.0.2:1234
AllowedIPs = 10.0.0.0/16,10.1.0.0/16,10.2.0.0/16
EOF

wg setconf wg0 /tmp/wg.conf
ip l set up dev wg0
ip r add 10.2.0.0/16 dev wg0


# perf stat -a -A -x , --cpu=0,1,2 -dd -- sleep 30
