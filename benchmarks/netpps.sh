#!/bin/bash

set -e

if [ -z "$1" ]; then
        echo
        echo usage: $0 [network-interface] ...
        echo
        echo e.g. $0 eth0
        echo
        echo shows packets-per-second
        exit
fi

IFS="${@:1}"

sleepUntilFullSecond() {
        sleep "$(echo "scale=6; (1000000000-$(date +%N))/1000000000" | bc)s"
}

declare -A ifs

for if in "${@:1}";
do
        ifs["$if"_rx]=`cat /sys/class/net/"$if"/statistics/rx_packets`
        ifs["$if"_tx]=`cat /sys/class/net/"$if"/statistics/tx_packets`
done

echo "# time, interface, rx_mpps, tx_mpps"

while true
do
        sleepUntilFullSecond
        for if in "${@:1}";
        do
                R1="${ifs["$if"_rx]}"
                T1="${ifs["$if"_tx]}"
                R2=`cat /sys/class/net/"$if"/statistics/rx_packets`
                T2=`cat /sys/class/net/"$if"/statistics/tx_packets`
                TXMPPS=`echo "scale=3; ($T2 - $T1) / 1000000" | bc`
                RXMPPS=`echo "scale=3; ($R2 - $R1) / 1000000" | bc`
                echo "$(date -Iseconds), $if, $RXMPPS, $TXMPPS"
                ifs["$if"_rx]=$R2
                ifs["$if"_tx]=$T2
        done
done
