#!/bin/sh
set -x
DIR=`date "+%Y%m%d-%H%M%S"`
RESTART=${1:-no}
SDN_IPS=${2:-10.61.80.240 10.61.80.241 10.61.80.242}
SDN_UNIX_USER=${3:-root}
TOPOLOGY_FILE=${4:-prod-topo.yml}
SDN_PROTOCOL=${5:-https}
SDN_PORT=${6:-8443}
FMCHECK=${7:-./fmcheck}

echo "gathering all services logs"

mkdir -p sdn_logs/$DIR

services=("eline" "path" "etree" "treepath" "cluster" "topology" "srtopology")
services_url=("brocade-bsc-eline:elines" "brocade-bsc-path:paths" "brocade-bsc-etree:etrees" "brocade-bsc-tree-path:treepaths" "entity-owners:entity-owners" "network-topology:network-topology/topology/flow:1" "network-topology:network-topology/topology/flow:1:sr")

for ip in $SDN_IPS
do

  END=${#services[@]}
  for ((i=0;i<END;i++))
  do
    final_file=sdn_logs/$DIR/${services[$i]}.config.json.${ip}
    curl -s --insecure --request GET -w "${http_code}" \
    --url ${SDN_PROTOCOL}://$ip:${SDN_PORT}/restconf/config/${services_url[$i]} \
    --header 'accept: application/json' \
    --header 'authorization: Basic YWRtaW46YWRtaW4=' \
    -o $final_file
  done

  for ((i=0;i<END;i++))
  do
    final_file=sdn_logs/$DIR/${services[$i]}.operational.json.${ip}
    curl -s --insecure --request GET -w "${http_code}" \
    --url ${SDN_PROTOCOL}://$ip:${SDN_PORT}/restconf/operational/${services_url[$i]} \
    --header 'accept: application/json' \
    --header 'authorization: Basic YWRtaW46YWRtaW4=' \
    -o $final_file
  done

done


$FMCHECK nodes -t $TOPOLOGY_FILE >> sdn_logs/$DIR/fmcheck_nodes.txt
$FMCHECK links -t $TOPOLOGY_FILE >> sdn_logs/$DIR/fmcheck_links.txt
$FMCHECK nodes -r -t $TOPOLOGY_FILE >> sdn_logs/$DIR/fmcheck_nodes_sr.txt
$FMCHECK links -r -t $TOPOLOGY_FILE >> sdn_logs/$DIR/fmcheck_links_sr.txt
$FMCHECK roles -t $TOPOLOGY_FILE >> sdn_logs/$DIR/fmcheck_roles.txt
$FMCHECK flows -t $TOPOLOGY_FILE >> sdn_logs/$DIR/fmcheck_flows.txt
$FMCHECK get-eline-stats-all -t $TOPOLOGY_FILE  >> sdn_logs/$DIR/fmcheck_elines_stats.txt
$FMCHECK get-eline-summary-all -t $TOPOLOGY_FILE  >> sdn_logs/$DIR/fmcheck_elines_summary.txt
$FMCHECK get-etree-stats-all -t $TOPOLOGY_FILE  >> sdn_logs/$DIR/fmcheck_etrees_stats.txt
$FMCHECK get-etree-summary-all -t $TOPOLOGY_FILE  >> sdn_logs/$DIR/fmcheck_etrees_summary.txt
$FMCHECK get-sr-summary-all -t $TOPOLOGY_FILE  >> sdn_logs/$DIR/fmcheck_sr_summary.txt
$FMCHECK get-flow-stats-all -t $TOPOLOGY_FILE  >> sdn_logs/$DIR/fmcheck_flow_stats.txt
$FMCHECK get-group-stats-all -t $TOPOLOGY_FILE  >> sdn_logs/$DIR/fmcheck_groups_stats.txt


if [ "$RESTART" == "yes" ]
then
  for ip in $SDN_IPS
  do
    ssh ${SDN_UNIX_USER}@${ip} 'sudo service brcd-bsc stop; sudo service brcd-ui stop; sudo killall java; sudo killall node'
  done
fi

for ip in $SDN_IPS
do

  echo "gathering all sdn logs from $ip"

  ssh ${SDN_UNIX_USER}@${ip} "rm -rf /opt/brocade/bsc/ctrlr*zip; sudo /opt/brocade/bsc/bin/support_diagnostics"
  scp ${SDN_UNIX_USER}@${ip}:/opt/brocade/bsc/ctrlr*zip sdn_logs/$DIR
  ssh ${SDN_UNIX_USER}@${ip} "mkdir $DIR; cp -r /opt/brocade/bsc/log/controller_logs/* $DIR; tar cvfz ${ip}-${DIR}.tar.gz $DIR; rm -rf $DIR;killall tcpdump"
  mkdir -p sdn_logs/$DIR
  scp ${SDN_UNIX_USER}@${ip}:~/${ip}-${DIR}.tar.gz sdn_logs/$DIR

  ssh ${SDN_UNIX_USER}@${ip} 'killall tcpump; gzip -9 ser*pcap'
  scp ${SDN_UNIX_USER}@${ip}:~/ser*pcap.gz sdn_logs/$DIR
  ssh ${SDN_UNIX_USER}@${ip} << EOF
  killall tcpdump
  rm -f server*pcap*
  nohup tcpdump -i any -G 86400 -W 1 -w server_\$HOSTNAME.pcap "port 6653" > /dev/null 2>&1 &
  EOF
  ssh ${SDN_UNIX_USER}@${ip} 'ps -ef | grep tcpdump'
  ssh ${SDN_UNIX_USER}@${ip} "rm ${ip}-${DIR}.tar.gz"

done

if [ "$RESTART" == "yes" ]
then
  for ip in $SDN_IPS
  do
    ssh ${SDN_UNIX_USER}@${ip} 'rm -rf /opt/brocade/bsc/log/controller_logs/*;sudo service brcd-bsc start; sudo service brcd-ui start'
  done
fi
