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
  fmcheck links [-s] [--topology=FILE] [--controller=IP]...
  fmcheck nodes [-s] [--topology=FILE] [--controller=IP]...
  fmcheck flows [-a] [--topology=FILE] [--controller=IP]...
  fmcheck roles [--topology=FILE] [--controller=IP]...
  fmcheck random-reboot-controller [--topology=FILE]
  fmcheck reboot-controller <name> [--topology=FILE]
  fmcheck random-reboot-switch [--topology=FILE]
  fmcheck reboot-switch <name> [--topology=FILE]
  fmcheck random-break-gw-switch <seconds> [--topology=FILE]
  fmcheck break-gw-switch <name> <seconds> [--topology=FILE]
  fmcheck random-delete-groups [--topology=FILE]
  fmcheck delete-groups <name> [--topology=FILE]
  fmcheck random-delete-flows [--topology=FILE]
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
  fmcheck (-h | --help)

Options:
  -h --help     Show this screen.
  -t, --topology=FILE   Topolofy file name [default: fm-topo.yml].
  -c, --controller=IP   Controller IP address
  -s --stopped      If Mininet is not running.
  -a --check-stats  Check flow/groups states with previous check
  --version     Show version.
```
