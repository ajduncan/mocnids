#!/bin/sh

# This captures specific data from host (src and dst)

HOST=$1
NOW=$(date +"%m_%d_%y_%H_%M_%S")
/usr/sbin/tcpdump -w /root/system/$HOST.$NOW 'host $HOST' &

