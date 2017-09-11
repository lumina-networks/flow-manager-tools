#!/bin/sh
set -x
DIR=`date "+%Y%m%d-%H%M%S"`
SDN_IPS=${1:-10.61.80.240 10.61.80.241 10.61.80.242}
SDN_UNIX_USER=${2:-root}
for ip in $SDN_IPS
do

echo "gathering and restarting tcpdump on $ip"

mkdir -p sdn_logs/$DIR
ssh ${SDN_UNIX_USER}@${ip} 'killall tcpump; gzip -9 ser*pcap'
scp ${SDN_UNIX_USER}@${ip}:~/ser*pcap.gz sdn_logs/$DIR
ssh ${SDN_UNIX_USER}@${ip} 'rm -f server*pcap*; nohup tcpdump -i any -G 86400 -W 1 -w server_$HOSTNAME.pcap "port 6653" &'
done
