#!/bin/bash

kill -TERM $(cat /tmp/netpps.pid)
kill -TERM $(cat /tmp/perf.pid)
