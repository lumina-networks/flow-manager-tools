echo "Checking links"
./fmcheck links -t fm-topo.yml 
echo "Checking nodes"
./fmcheck nodes -t fm-topo.yml 
# echo "Checking flows"
# ./fmcheck flows -t fm-topo.yml 
# echo "Checking links -sr"
# ./fmcheck links -sr -t fm-topo.yml
# echo "Checking nodes -sr" 
# ./fmcheck nodes -sr -t fm-topo.yml 
echo "Checking roles"
./fmcheck roles -t fm-topo.yml 

# echo "reboot-random-controller"
# ./fmcheck reboot-random-controller -t fm-topo.yml
# echo "reboot-random-controller"
# ./fmcheck reboot-controller-by-random-switch -t fm-topo.yml

# echo "reboot-random-switch"
# ./fmcheck reboot-random-switch -t fm-topo.yml
# echo "reboot-random-switch"
# ./fmcheck reboot-switch n200 -t fm-topo.yml

# ./fmcheck break-random-gw-switch 10 -t fm-topo.yml
# ./fmcheck break-gw-switch n100 5 -t fm-topo.yml
# ./fmcheck break-random-ctrl-switch 10 -t fm-topo.yml
# ./fmcheck break-ctrl-switch n100 <controller_name> <seconds> -t fm-topo.yml
# ./fmcheck isolate-random-ctrl <seconds> -t fm-topo.yml
# ./fmcheck isolate-ctrl <controller_name> <seconds> -t fm-topo.yml
# ./fmcheck isolate-random-ctrl-switch <seconds> -t fm-topo.yml
# ./fmcheck isolate-ctrl-switch <switch_name> <seconds> -t fm-topo.yml
# ./fmcheck delete-random-groups -t fm-topo.yml
# ./fmcheck delete-groups <name> -t fm-topo.yml
# ./fmcheck delete-random-flows -t fm-topo.yml
# ./fmcheck delete-flows <name> -t fm-topo.yml
./fmcheck get-flow-stats-all -t fm-topo.yml
./fmcheck get-flow-stats 0 -t fm-topo.yml
./fmcheck get-flow-node-stats-all openflow:100 -t fm-topo.yml
./fmcheck get-flow-node-stats openflow:100 0 -t fm-topo.yml
./fmcheck get-group-stats-all -t fm-topo.yml
./fmcheck get-group-stats 0 -t fm-topo.yml
./fmcheck get-group-node-stats-all openflow:100 -t fm-topo.yml
./fmcheck get-group-node-stats openflow:100 0 -t fm-topo.yml
echo "checking Eline"
./fmcheck get-eline-stats-all -t fm-topo.yml
./fmcheck get-eline-stats 0 -t fm-topo.yml
./fmcheck get-eline-summary-all -t fm-topo.yml
./fmcheck get-eline-summary 0 -t fm-topo.yml
echo "checking Etree"
./fmcheck get-etree-stats-all -t fm-topo.yml
./fmcheck get-etree-stats 0 -t fm-topo.yml
./fmcheck get-etree-summary-all -t fm-topo.yml
./fmcheck get-etree-summary 0 -t fm-topo.yml
# ./fmcheck get-sr-summary-all -t fm-topo.yml
# ./fmcheck get-sr-summary <source> <destination> -t fm-topo.yml
./fmcheck get-node-summary -t fm-topo.yml
# ./fmcheck (-h | --help)