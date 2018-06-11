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

while true
do
        R1=`cat /sys/class/net/$1/statistics/rx_packets`
        T1=`cat /sys/class/net/$1/statistics/tx_packets`
        sleep $INTERVAL
        R2=`cat /sys/class/net/$1/statistics/rx_packets`
        T2=`cat /sys/class/net/$1/statistics/tx_packets`
        TXPPS=`expr $T2 - $T1`
        RXPPS=`expr $R2 - $R1`
        echo "TX $1: $TXPPS pkts/s RX $1: $RXPPS pkts/s"
done
