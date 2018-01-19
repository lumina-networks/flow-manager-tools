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
* **coloredlogs**

## Usage

`fmcheck` validates if links, nodes and flows are in sync between the switch, configuration and operational data store. It also provides the ability to restart a switch or controller and delete all flows or groups directly from a switch. Finally, it also provides commands to obtain flow/group/services stats.

**Working:**
```
$ fmcheck -h
Flow Manager Testing Tools

Usage:
  fmcheck links [-srd] [--topology=FILE] [--controller=IP]...
  fmcheck nodes [-srd] [--topology=FILE] [--controller=IP]...
  fmcheck flows [-ad] [--topology=FILE] [--controller=IP]...
  fmcheck roles [-d] [--topology=FILE] [--controller=IP]...

  fmcheck reboot-random-controller [-d] [--topology=FILE]
  fmcheck reboot-controller <name> [-d] [--topology=FILE]
  fmcheck reboot-controller-by-switch <name> [-d] [--topology=FILE]
  fmcheck reboot-controller-by-random-switch [-d] [--topology=FILE]
  fmcheck reboot-random-switch [-d] [--topology=FILE]
  fmcheck reboot-switch <name> [-d] [--topology=FILE]

  fmcheck get-flow-stats-all [-d] [--topology=FILE]
  fmcheck get-flow-stats <filter>... [-d] [--topology=FILE]
  fmcheck (-h | --help)

Options:
  -h --help     Show this screen.
  -t, --topology=FILE   Topolofy file name [default: fm-topo.yml].
  -c, --controller=IP   Controller IP address
  -s --stopped      If Mininet is not running.
  -r --segementrouting  Use segment routing topology.
  -a --check-stats  Check flow/groups states with previous check
  -d --debug  Log debug level
  --version     Show version.
```

**Not working**
```
  fmcheck break-random-gw-switch <seconds> [-d] [--topology=FILE]
  fmcheck break-gw-switch <name> <seconds> [-d] [--topology=FILE]
  fmcheck break-random-ctrl-switch <seconds> [-d] [--topology=FILE]
  fmcheck break-ctrl-switch <switch_name> <controller_name> <seconds> [-d] [--topology=FILE]

  fmcheck isolate-random-ctrl <seconds> [-d] [--topology=FILE]
  fmcheck isolate-ctrl <controller_name> <seconds> [-d] [--topology=FILE]
  fmcheck isolate-random-ctrl-switch <seconds> [-d] [--topology=FILE]
  fmcheck isolate-ctrl-switch <switch_name> <seconds> [-d] [--topology=FILE]

  fmcheck delete-random-groups [-d] [--topology=FILE]
  fmcheck delete-groups <name> [-d] [--topology=FILE]
  fmcheck delete-random-flows [-d] [--topology=FILE]
  fmcheck delete-flows <name> [-d] [--topology=FILE]

  fmcheck get-flow-node-stats-all <node> [-d] [--topology=FILE]
  fmcheck get-flow-node-stats <node> <filter>... [-d] [--topology=FILE]
  fmcheck get-group-stats-all [-d] [--topology=FILE]
  fmcheck get-group-stats <filter>... [-d] [--topology=FILE]
  fmcheck get-group-node-stats-all <node> [-d] [--topology=FILE]
  fmcheck get-group-node-stats <node> <filter>... [-d] [--topology=FILE]
  fmcheck get-eline-stats-all [-d] [--topology=FILE]
  fmcheck get-eline-stats <filter>... [-d] [--topology=FILE]
  fmcheck get-eline-summary-all [-d] [--topology=FILE]
  fmcheck get-eline-summary <filter>... [-d] [--topology=FILE]
  fmcheck get-etree-stats-all [-d] [--topology=FILE]
  fmcheck get-etree-stats <filter>... [-d] [--topology=FILE]
  fmcheck get-etree-summary-all [-d] [--topology=FILE]
  fmcheck get-etree-summary <filter>... [-d] [--topology=FILE]
  fmcheck get-sr-summary-all [-d] [--topology=FILE]
  fmcheck get-sr-summary <source> <destination> [-d] [--topology=FILE]
  fmcheck get-node-summary [-d] [--topology=FILE]
```
