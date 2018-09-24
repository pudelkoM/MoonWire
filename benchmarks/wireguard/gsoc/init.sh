#!/bin/bash

set -e

apt-get install -y libmnl-dev libelf-dev linux-headers-$(uname -r) build-essential pkg-config
apt-get remove -y wireguard wireguard-dkms || true

pushd ~
git clone https://git.zx2c4.com/WireGuard
popd
