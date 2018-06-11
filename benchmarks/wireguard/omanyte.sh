!/bin/bash

set -e
set -x

apt-get update
apt-get install -y linux-tools-4.4.0-109-generic
apt-get install -y software-properties-common
add-apt-repository ppa:wireguard/wireguard
apt-get update
apt-get install -y wireguard

ip a add 10.0.1.2/24 dev ens1f0
ip a add 10.0.0.2/24 dev enp2s0f0
ip l set up dev ens1f0
ip l set up dev enp2s0f0
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
