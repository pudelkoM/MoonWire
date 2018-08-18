#!/bin/bash

if [ -z "$3" ]; then
    echo "Usage: $0 [packet size] [send rate] [cpu]"
    exit
fi


PKT_SIZE=$1
SENDRATE=$2
CPU=$3

../netpps.sh wg0 1 > /tmp/wg_bench_$(date -Iseconds)_$PKT_SIZE@$SENDRATE.txt & echo $! > /tmp/netpps.pid

perf record --delay=1000 -c 10000000 -g -cpu $CPU -o /tmp/perf_$PKT_SIZE@SENDRATE.data -- sleep 999 & echo $! > /tmp/perf.pid
# perf report -i /tmp/perf.data --cpu X -g none --no-children --sort symbol --stdio