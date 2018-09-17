#!/bin/bash

set -e
set -x

PKT_SIZE=60
REMOTE=cesis

for rate in $(seq 25 25 500)
do
    echo $rate;
    ssh $REMOTE "cd ./MoonWire/benchmarks/wireguard; and ./omanyte_start_record.sh $PKT_SIZE $rate 0"
    ./libmoon/build/libmoon benchmarks/pktgen-fixed.lua --size=$PKT_SIZE -t 1 -s 30 --rate=$rate 1
    ssh $REMOTE "cd ./MoonWire/benchmarks/wireguard; and ./omanyte_stop_record.sh"
done
