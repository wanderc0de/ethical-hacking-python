#! /bin/bash
sysctl net.ipv4.ip_forward=1 
iptables -I FORWARD -j NFQUEUE --queue-num 0