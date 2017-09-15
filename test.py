#!/usr/bin/env python

from fmtopo.topo import _get_switch_port_status_noviflow, _get_switch_version_noviflow
from pprint import pprint

#ports = _get_switch_port_status_noviflow('10.193.49.20', 22, 'superuser', 'Telstra123')
#PORTS = {}
#PORTS['test'] = ports
#pprint(PORTS)

version = _get_switch_version_noviflow('10.193.49.20', 22, 'superuser', 'Telstra123')
print version
