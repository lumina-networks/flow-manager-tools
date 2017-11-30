#!/bin/sh
set -x
LOG_DIR="/var/log/sdn_logs"
DIR=`date "+%Y%m%d-%H%M%S"`
SDN_IPS=${1:-10.61.80.240 10.61.80.241 10.61.80.242}
SDN_UNIX_USER=${2:-root}


if [ ! -d $LOG_DIR ]; then
  echo "Cannot proceed. $LOG_DIR not available"
  exit 1
fi


for ip in $SDN_IPS
do

echo "gathering and restarting tcpdump on $ip"

mkdir -p $LOG_DIR/$DIR
ssh ${SDN_UNIX_USER}@${ip} 'killall tcpdump; gzip -9 ser*pcap'
scp ${SDN_UNIX_USER}@${ip}:~/ser*pcap.gz $LOG_DIR/$DIR
ssh ${SDN_UNIX_USER}@${ip} << EOF
killall tcpdump
rm -f server*pcap*
nohup tcpdump -i any -G 86400 -W 1 -w server_\$HOSTNAME.pcap "port 6653" > /dev/null 2>&1 &
EOF
ssh ${SDN_UNIX_USER}@${ip} 'ps -ef | grep tcpdump'
done
