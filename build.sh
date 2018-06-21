#!/bin/bash

set -e

git submodule update --init

cd src/libsodium/
mkdir build
./configure --prefix $(realpath ./build/) --exec-prefix $(realpath ./build/)
make
make install
cd ..
