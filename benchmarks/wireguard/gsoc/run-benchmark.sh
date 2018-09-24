#!/bin/bash

set -e
set -x

NAME=$1
REMOTE=omanyte
SIZE=60
FLOWS=1024

for RATE in $(seq 50 50 1000)
do
    ssh $REMOTE "./MoonWire/libmoon/build/libmoon ./MoonWire/benchmarks/pktgen-fixed.lua --threads=2 --pktLen=$SIZE --rate=$RATE --flows=$FLOWS 0 > /dev/null" &
    ssh_pid=$!
    sleep 5
    ../../netpps.sh ens3f0 wg0 ens4f0 > "$NAME"_"$SIZE"@"$RATE"_"$FLOWS"_flows.csv &
    pid=$!
    # TODO: perf stat, record ...
    sleep 20
    kill -TERM $pid
    kill -TERM $ssh_pid
    ssh $REMOTE "pkill libmoon"
    sleep 3
done
