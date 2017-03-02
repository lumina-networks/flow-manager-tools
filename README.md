# Flow Manager Tools

This tools provides a mechanism to quickly test flow manager with OVS and/or Noviflow switches.

- [Install](#install)
- [Usage](#usage)
  - [Flow Manager Tester](flow-manager-tester)

## Install

### From source

```
git clone <this-project-git-url>
cd flow-manager-tools
sudo python setup.py install
```

### Dependencies

* **pexpect**
* **pyyaml**
* **requests**

## Usage

`fmcheck` validates if links, nodes and flows are in sync between the switch, configuration and operational data store. It also provides the ability to restart a switch or controller and delete all flows or groups directly from a switch.

```
$ fmcheck -h
Flow Manager Testing Tools

Usage:
  fmcheck links [-s] [--topology=FILE] [--controller=IP]...
  fmcheck nodes [-s] [--topology=FILE] [--controller=IP]...
  fmcheck flows [-a] [--topology=FILE] [--controller=IP]...
  fmcheck random-reboot-controller [--topology=FILE]
  fmcheck reboot-controller <name> [--topology=FILE]
  fmcheck random-reboot-switch [--topology=FILE]
  fmcheck reboot-switch <name> [--topology=FILE]
  fmcheck random-delete-groups [--topology=FILE]
  fmcheck delete-groups <name> [--topology=FILE]
  fmcheck random-delete-flows [--topology=FILE]
  fmcheck delete-flows <name> [--topology=FILE]
  fmcheck (-h | --help)

Options:
  -h --help     Show this screen.
  -t, --topology=FILE   Topolofy file name [default: fm-topo.yml].
  -c, --controller=IP   Controller IP address
  -s --stopped      If Mininet is not running.
  -a --check-stats  Check flow/groups states with previous check
  --version     Show version.
```

### Flow Manager Tester
