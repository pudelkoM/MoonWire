#!/bin/bash

set -e

git submodule update --init --recursive

# Build libsodium
cd src/libsodium/
mkdir build
./configure --prefix $(realpath ./build/) --exec-prefix $(realpath ./build/)
make
make install
cd ../../

# Build libmoon
cd libmoon
sudo apt-get install git build-essential cmake linux-headers-`uname -r` lshw libnuma-dev
./build.sh
./setup-hugetlbfs.sh
cd ..

# Build helpers
mkdir build
cd build
cmake ..
make
cd ..


echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
