#!/bin/bash

set -e

git submodule update --init

cd libsodium-1.0.16/
mkdir build
./configure --prefix $(realpath ./build/) --exec-prefix $(realpath ./build/)
make
make install
