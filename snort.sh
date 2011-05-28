#!/bin/sh

snort -r /root/system/bt4_attack.pcap -c /etc/snort/snort.conf -A full
