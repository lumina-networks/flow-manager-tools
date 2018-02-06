# Flow Manager Tools

This tool provides a mechanism to test and validate Flow Manager application with OVS and Noviflow switches. It also includes getting eline/etree/flows/groups stats and summary information and other intrusive disruptive actions such as rebooting switches or deleting flows/groups to validate system recovery.

- [Install](#install)
- [Usage](#usage)

## Install

### From source

```
git clone https://github.com/qasimraz/flow-manager-tools.git
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

`fmcheck2` validates if links, nodes and flows are in sync between the switch, configuration and operational data store. It also provides the ability to restart a switch or controller and delete all flows or groups directly from a switch. Finally, it also provides commands to obtain flow/group/services stats.

## fmcheck2
`fmcheck2` will be the command after installation, despite the output in the help file. This is to allow users to test `fmcheck` and `fmcheck2` side by side. Eventually `fmcheck2` will become `fmcheck`.

**Working:**
```
$ fmcheck2 -h
Flow Manager Testing Tools

Usage:
  fmcheck links [-srd] [--topology=FILE] [--controller=IP]...
  fmcheck nodes [-srd] [--topology=FILE] [--controller=IP]...
  fmcheck flows [-ad] [--topology=FILE] [--controller=IP]...
  fmcheck roles [-d] [--topology=FILE] [--controller=IP]...
  fmcheck sync-status [-d] [--topology=FILE] [--controller=IP]...

  fmcheck reboot-random-controller [-d] [--topology=FILE]
  fmcheck reboot-controller <name> [-d] [--topology=FILE]
  fmcheck reboot-controller-by-switch <name> [-d] [--topology=FILE]
  fmcheck reboot-controller-by-random-switch [-d] [--topology=FILE]
  fmcheck reboot-random-switch [-d] [--topology=FILE]
  fmcheck reboot-switch <name> [-d] [--topology=FILE]
  fmcheck reboot-controller-vm <name> [-d] [--topology=FILE]
  fmcheck reboot-random-controller-vm [-d] [--topology=FILE]

  fmcheck isolate-random-ctrl <seconds> [-d] [--topology=FILE]
  fmcheck isolate-ctrl <controller_name> <seconds> [-d] [--topology=FILE]
  fmcheck isolate-random-ctrl-switch <seconds> [-d] [--topology=FILE]
  fmcheck isolate-ctrl-switch <switch_name> <seconds> [-d] [--topology=FILE]

  fmcheck break-random-gw-switch <seconds> [-d] [--topology=FILE]
  fmcheck break-gw-switch <name> <seconds> [-d] [--topology=FILE]
  fmcheck break-random-ctrl-switch <seconds> [-d] [--topology=FILE]
  fmcheck break-ctrl-switch <switch_name> <controller_name> <seconds> [-d] [--topology=FILE]

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
  
  fmcheck get-flow-stats-all [-d] [--topology=FILE]
  fmcheck get-flow-stats <filter>... [-d] [--topology=FILE]
  fmcheck (-h | --help)
  
Options:
  -h --help     Show this screen.
  -d --debug  Log debug level
  -t, --topology=FILE   Topolofy file name [default: fm-topo.yml].
  -c, --controller=IP   Controller IP address
  -s --stopped      If Mininet is not running.
  -r --segementrouting  Use segment routing topology.
  -a --check-stats  Check flow/groups states with previous check
  --version     Show version.
```

**To Do**
```
  OVS compatibility

  Documentation

  fmcheck download controller logs
  fmcheck clear controller logs
    
  fmcheck versions of controllers
  fmcheck versions of switches

  replace print statements with logging

    --Check if operational datastore and configurational datastore match

  fmcheck isolate-switch 
    --Break connection between switch and controller by adding iptable rules into controller

  fmcheck get-sr-summary-all [-d] [--topology=FILE]
  fmcheck get-sr-summary <source> <destination> [-d] [--topology=FILE]
    --Catch filter errors

  fmcheck isolate-ctrl-switch <switch_name> <seconds> [-d] [--topology=FILE]
    --Clean up log messages

  fmcheck reboot-random-controller [-d] [--topology=FILE]
  fmcheck reboot-controller <name> [-d] [--topology=FILE]
  fmcheck reboot-controller-by-switch <name> [-d] [--topology=FILE]
  fmcheck reboot-controller-by-random-switch [-d] [--topology=FILE]
    --Check if local or ssh/remote controller

  fmcheck reboot-all-controllers
  fmcheck reboot-all-switches
    --New features

  fmcheck get-etree-hop-stats
    --New feature to measure pathing efficiency for elines and etree
  
  fmcheck test-resilience
    --A test suite that runs continuously and outputs issues with the controller

  fmcheck patch-upload

  fmcheck execute-on-controller <controller> <command>
  fmcheck execute-on-all-controllers <command>

  fmcheck execute-on-switch <controller> <command>
  fmcheck execute-on-all-switches <command>
```

**Long Term Project**
```
  Cross controller compatibility
  Abstraction of controller
```