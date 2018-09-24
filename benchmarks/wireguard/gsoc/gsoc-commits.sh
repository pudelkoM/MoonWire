#!/bin/bash

set -e
set -x

PREFIX=$1
REMOTE=omanyte

# typos, whitespace, tests, etc
boring_commit=(590c41089fd77bf43efda375c0e6bd3913cb9350 0f8718b4fcbb89abc8b8b25c09510e1f7fac9625 18822b84f88422f11611c598a0c23c56652693d9 856f10593d2fc8b87992d9c5c556ddf108d313e8)

# actual code changes
interresting_commits=(
    b289d122d8fe935de7138f77a8495dca76555b0e
    6008eacbf2c7a5f31b0c9d5d0a629cbdfbb8f222
    5e3532eb1895ccdd0a53d14b47d7fc85234f7866
    5e4689d79a7a8aec803cdc2da8a0056dc08370c5
    fe5f0f661797b41648eac64b40e5038b25175047
    tg/mpmc_ring
    tg/mpmc-benchmark
)

declare -A cases

# MPMC-wip, final (?) version of both students
#cases[mpmc-wip_baseline]=dfd9827d5b08c506522bb3762cd3b0dbac640bbc
#cases[mpmc-wip_head]=5e4689d79a7a8aec803cdc2da8a0056dc08370c5

# mpmc-benchmark, same as MPMC-wip + preemption patch
#cases[mpmc-benchmark-baseline]=dfd9827d5b08c506522bb3762cd3b0dbac640bbc
#cases[mpmc-benchmark-head]=6f909b2abc055ecb17dbf4d80f93e2ed84b264d5

# MPMC_ring, tg version pre-merge
#cases[mpmc_ring_baseline]=a59b4d5808e8cd8da8a9f1db6be71a200a9d716c
#cases[mpmc_ring_head]=0df81af3d435aaf29f3dee813c4b30952845e97e


SIZE=60

for CASE in "${!cases[@]}"
do
    COMMIT="${cases[$CASE]}"
    ./setup-version.sh "$COMMIT"
    ./run-benchmark.sh $CASE
done
