#!/bin/bash

set -e
set -x

# Rx device
for irq in 75 76 77 78 79 80 81 82 83 84 85 86
do
    echo 0 > /proc/irq/$irq/smp_affinity_list
done

# Tx device
for irq in 147 148 149 150 151 152 153 154 155 156 157 158
do
    echo 1 > /proc/irq/$irq/smp_affinity_list
done
