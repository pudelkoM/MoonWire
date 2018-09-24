#!/bin/bash

set -e

if [ ! -d $(realpath ~/WireGuard/) ]; then
        echo "WireGuard git repo not found at ~/WireGuard!"
        echo "Run ./init.sh first!"
        exit 1
fi

if [ -z "$1" ]; then
        echo
        echo usage: $0 [git tag, version or commit]
        echo
        echo e.g. $0 0.0.20171221
        exit 1
fi

pushd ~/WireGuard/src

# Small hack for one broken commit
git update-index --no-assume-unchanged src/version.h || true

git checkout -f "$1"

# Fix broken includes
git apply -3 ~/MoonWire/benchmarks/wireguard/gsoc/fix-includes.patch || true

ip l del dev wg0 || true
modprobe -r wireguard || true

make
make install


# copy&paste from general setup
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

popd
