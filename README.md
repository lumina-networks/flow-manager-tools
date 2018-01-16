# Flow Manager Tools

This tool provides a mechanism to test and validate Flow Manager application with OVS and Noviflow switches. It also includes getting eline/etree/flows/groups stats and summary information and other intrusive disruptive actions such as rebooting switches or deleting flows/groups to validate system recovery.

- [Install](#install)
- [Usage](#usage)

## Install

### From source

```
git clone https://github.com/lumina-networks/flow-manager-tools
cd flow-manager-tools
sudo python setup.py install
```

### Dependencies

Following dependencies are installed with the installation.

* **pexpect**
* **pyyaml**
* **requests**

## Usage

`fmcheck` validates if links, nodes and flows are in sync between the switch, configuration and operational data store. It also provides the ability to restart a switch or controller and delete all flows or groups directly from a switch. Finally, it also provides commands to obtain flow/group/services stats.

```
$ fmcheck -h
Flow Manager Testing Tools

Usage:
  fmcheck links [-s] [-r] [--topology=FILE] [--controller=IP]...
  fmcheck nodes [-s] [-r] [--topology=FILE] [--controller=IP]...
  fmcheck flows [-a] [--topology=FILE] [--controller=IP]...
  fmcheck roles [--topology=FILE] [--controller=IP]...
  
  fmcheck reboot-random-controller [--topology=FILE]
  fmcheck reboot-controller <name> [--topology=FILE]
  fmcheck reboot-controller-by-switch <name> [--topology=FILE]
  fmcheck reboot-controller-by-random-switch [--topology=FILE]
  fmcheck reboot-random-switch [--topology=FILE]
  fmcheck reboot-switch <name> [--topology=FILE]
  
  fmcheck break-random-gw-switch <seconds> [--topology=FILE]
  fmcheck break-gw-switch <name> <seconds> [--topology=FILE]
  fmcheck break-random-ctrl-switch <seconds> [--topology=FILE]
  fmcheck break-ctrl-switch <switch_name> <controller_name> <seconds> [--topology=FILE]
  
  fmcheck isolate-random-ctrl <seconds> [--topology=FILE]
  fmcheck isolate-ctrl <controller_name> <seconds> [--topology=FILE]
  fmcheck isolate-random-ctrl-switch <seconds> [--topology=FILE]
  fmcheck isolate-ctrl-switch <switch_name> <seconds> [--topology=FILE]

  fmcheck delete-random-groups [--topology=FILE]
  fmcheck delete-groups <name> [--topology=FILE]
  fmcheck delete-random-flows [--topology=FILE]
  fmcheck delete-flows <name> [--topology=FILE]

  fmcheck get-flow-stats-all [--topology=FILE]
  fmcheck get-flow-stats <filter>... [--topology=FILE]
  fmcheck get-flow-node-stats-all <node> [--topology=FILE]
  fmcheck get-flow-node-stats <node> <filter>... [--topology=FILE]
  fmcheck get-group-stats-all [--topology=FILE]
  fmcheck get-group-stats <filter>... [--topology=FILE]
  fmcheck get-group-node-stats-all <node> [--topology=FILE]
  fmcheck get-group-node-stats <node> <filter>... [--topology=FILE]
  fmcheck get-eline-stats-all [--topology=FILE]
  fmcheck get-eline-stats <filter>... [--topology=FILE]
  fmcheck get-eline-summary-all [--topology=FILE]
  fmcheck get-eline-summary <filter>... [--topology=FILE]
  fmcheck get-etree-stats-all [--topology=FILE]
  fmcheck get-etree-stats <filter>... [--topology=FILE]
  fmcheck get-etree-summary-all [--topology=FILE]
  fmcheck get-etree-summary <filter>... [--topology=FILE]
  fmcheck get-sr-summary-all [--topology=FILE]
  fmcheck get-sr-summary <source> <destination> [--topology=FILE]
  fmcheck get-node-summary [--topology=FILE]
  fmcheck (-h | --help)

Options:
  -h --help     Show this screen.
  -t, --topology=FILE   Topolofy file name [default: fm-topo.yml].
  -c, --controller=IP   Controller IP address
  -s --stopped      If Mininet is not running.
  -r --segementrouting  Use segment routing topology.
  -a --check-stats  Check flow/groups states with previous check
  --version     Show version.
```
