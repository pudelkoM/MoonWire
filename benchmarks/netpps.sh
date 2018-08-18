#!/bin/bash


if [ -z "$2" ]; then
        echo
        echo usage: $0 [network-interface] [interval]
        echo
        echo e.g. $0 eth0 1
        echo
        echo shows packets-per-second
        exit
fi

IF=$1
INTERVAL="$2"  # update interval in seconds

R1=`cat /sys/class/net/$1/statistics/rx_packets`
T1=`cat /sys/class/net/$1/statistics/tx_packets`

echo "# time, interface, tx_mpps, rx_mpps"

while true
do
        sleep $INTERVAL
        R2=`cat /sys/class/net/$1/statistics/rx_packets`
        T2=`cat /sys/class/net/$1/statistics/tx_packets`
        TXMPPS=`echo "scale=2; ($T2 - $T1) / ($INTERVAL * 1000000)" | bc`
        RXMPPS=`echo "scale=2; ($R2 - $R1) / ($INTERVAL * 1000000)" | bc`
        echo "$(date -Iseconds), $1, $TXMPPS, $RXMPPS"
        R1=$R2
        T1=$T2
done
