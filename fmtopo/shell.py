"""Flow Manager Testing Tools

Usage:
  fmcheck links [-s] [-r] [--topology=FILE] [--controller=IP]...
  fmcheck nodes [-s] [-r] [--topology=FILE] [--controller=IP]...
  fmcheck flows [-a] [--topology=FILE] [--controller=IP]...
  fmcheck roles [--topology=FILE] [--controller=IP]...
  fmcheck sync-status [--topology=FILE] [--controller=IP]...
  fmcheck random-reboot-controller [--topology=FILE]
  fmcheck reboot-controller <name> [--topology=FILE]
  fmcheck reboot-controller-by-switch <name> [--topology=FILE]
  fmcheck random-reboot-switch [--topology=FILE]
  fmcheck reboot-controller-by-random-switch [--topology=FILE]
  fmcheck reboot-switch <name> [--topology=FILE]
  fmcheck random-break-gw-switch <seconds> [--topology=FILE]
  fmcheck break-gw-switch <name> <seconds> [--topology=FILE]
  fmcheck reconnect-ctrl-switch <switch_name> [--topology=FILE]
  fmcheck reconnect-ctrl-all-switch [--topology=FILE]
  fmcheck random-break-ctrl-switch <seconds> [--topology=FILE]
  fmcheck break-ctrl-switch <switch_name> <controller_name> <seconds> [--topology=FILE]
  fmcheck random-isolate-ctrl <seconds> [--topology=FILE]
  fmcheck isolate-ctrl <controller_name> <seconds> [--topology=FILE]
  fmcheck random-isolate-ctrl-switch <seconds> [--topology=FILE]
  fmcheck isolate-ctrl-switch <switch_name> <seconds> [--topology=FILE]
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
  fmcheck get-node-summary [--topology=FILE]
  fmcheck (-h | --help)

Options:
  -h --help     Show this screen.
  -t, --topology=FILE   Topolofy file name [default: prod-topo.yml].
  -c, --controller=IP   Controller IP address
  -s --stopped      If Mininet is not running.
  -r --segementrouting  Use segment routing topology.
  -a --check-stats  Check flow/groups states with previous check
  --version     Show version.

"""

import os
import sys
import yaml
from docopt.docopt import docopt
import fmtopo.topo


class Shell(object):

    def __init__(self):
        arguments = docopt(__doc__, version='Flow Manager Testing Tools 1.0')

        file = 'prod-topo.yml'
        if arguments['--topology']:
            file = arguments['--topology']
        elif not (os.path.isfile(file)):
            file = 'mn-topo.yml'

        props = None
        if (os.path.isfile(file)):
            with open(file, 'r') as f:
                props = yaml.load(f)
        if props is None:
            file = 'mn-topo.yml'
            if (os.path.isfile(file)):
                with open(file, 'r') as f:
                    props = yaml.load(f)

        if props is None:
            print "ERROR: yml topology file not found"
            sys.exit(1)

        if arguments['--controller']:
            props['controller'] = []
            i = 0
            for ip in arguments['--controller']:
                props['controller'].append(
                    {'name': "c{}".format(i),
                     'ip': ip
                     })
                i = i + 1

        checker = fmtopo.topo.Topo(props)
        if arguments['links'] and arguments['--stopped']:
            if arguments['--segementrouting']:
                result = checker.check_links(False,'flow:1:sr')
            else:
                result = checker.check_links(False)
        elif arguments['links']:
            if arguments['--segementrouting']:
                result = checker.check_links(True,'flow:1:sr')
            else:
                result = checker.check_links()
        elif arguments['flows'] and arguments['--check-stats']:
            result = checker.check_flows(check_stats=True)
        elif arguments['flows']:
            result = checker.check_flows()
        elif arguments['nodes'] and arguments['--stopped']:
            if arguments['--segementrouting']:
                result = checker.check_nodes(False,'flow:1:sr')
            else:
                result = checker.check_nodes(False)
        elif arguments['nodes']:
            if arguments['--segementrouting']:
                result = checker.check_nodes(True,'flow:1:sr')
            else:
                result = checker.check_nodes()
        elif arguments['roles']:
            result = checker.check_roles()
        elif arguments['random-reboot-controller']:
            result = checker.reboot_controller(checker.get_random_controller())
        elif arguments['reboot-controller']:
            result = checker.reboot_controller(arguments['<name>'])
        elif arguments['random-reboot-switch']:
            result = checker.reboot_switch(checker.get_random_switch())
        elif arguments['reboot-controller-by-switch']:
            result = checker.reboot_controller(checker.get_master_controller_name(arguments['<name>']))
        elif arguments['reboot-controller-by-random-switch']:
            result = checker.reboot_controller(checker.get_master_controller_name(checker.get_random_switch()))
        elif arguments['break-gw-switch']:
            result = checker.break_gw_switch(arguments['<name>'],arguments['<seconds>'])
        elif arguments['random-break-gw-switch']:
            result = checker.break_gw_switch(checker.get_random_switch(), arguments['<seconds>'])
        elif arguments['reconnect-ctrl-switch']:
            for controller in checker.controllers_name:
                result = checker.break_controller_switch(arguments['<switch_name>'], controller, 0)
        elif arguments['reconnect-ctrl-all-switch']:
            for sw in checker.switches:
                for controller in checker.controllers_name:
                    result = checker.break_controller_switch(sw, controller, 0)
        elif arguments['break-ctrl-switch']:
            result = checker.break_controller_switch(arguments['<switch_name>'],arguments['<controller_name>'],arguments['<seconds>'])
        elif arguments['random-break-ctrl-switch']:
            name = checker.get_random_switch()
            result = checker.break_controller_switch(name, checker.get_master_controller_name(name), arguments['<seconds>'])
        elif arguments['isolate-ctrl']:
            result = checker.isolate_controller(arguments['<controller_name>'],arguments['<seconds>'])
        elif arguments['random-isolate-ctrl']:
            name = checker.get_random_controller()
            result = checker.isolate_controller(name, arguments['<seconds>'])
        elif arguments['isolate-ctrl-switch']:
            result = checker.isolate_controller(checker.get_master_controller_name(arguments['<switch_name>']),arguments['<seconds>'])
        elif arguments['random-isolate-ctrl-switch']:
            name = checker.get_random_switch()
            result = checker.isolate_controller(checker.get_master_controller_name(name), arguments['<seconds>'])
        elif arguments['reboot-switch']:
            result = checker.reboot_switch(arguments['<name>'])
        elif arguments['random-delete-groups']:
            result = checker.delete_groups(checker.get_random_switch())
        elif arguments['delete-groups']:
            result = checker.delete_groups(arguments['<name>'])
        elif arguments['random-delete-flows']:
            result = checker.delete_flows(checker.get_random_switch())
        elif arguments['delete-flows']:
            result = checker.delete_flows(arguments['<name>'])
        elif arguments['get-flow-stats-all']:
            result = checker.print_flow_stats()
        elif arguments['get-flow-stats']:
            result = checker.print_flow_stats(filters=arguments['<filter>'])
        elif arguments['get-flow-node-stats-all']:
            result = checker.print_flow_stats(node_name=arguments['<node>'])
        elif arguments['get-flow-node-stats']:
            result = checker.print_flow_stats(filters=arguments['<filter>'], node_name=arguments['<node>'])
        elif arguments['get-group-stats-all']:
            result = checker.print_group_stats()
        elif arguments['get-group-stats']:
            result = checker.print_group_stats(filters=arguments['<filter>'])
        elif arguments['get-group-node-stats-all']:
            result = checker.print_group_stats(node_name=arguments['<node>'])
        elif arguments['get-group-node-stats']:
            result = checker.print_group_stats(filters=arguments['<filter>'], node_name=arguments['<node>'])
        elif arguments['get-eline-stats-all']:
            result = checker.print_eline_stats()
        elif arguments['get-eline-stats']:
            result = checker.print_eline_stats(filters=arguments['<filter>'])
        elif arguments['get-eline-summary-all']:
            result = checker.print_eline_summary()
        elif arguments['get-eline-summary']:
            result = checker.print_eline_summary(filters=arguments['<filter>'])
        elif arguments['get-etree-stats-all']:
            result = checker.print_etree_stats()
        elif arguments['get-etree-stats']:
            result = checker.print_etree_stats(filters=arguments['<filter>'])
        elif arguments['get-etree-summary-all']:
            result = checker.print_etree_summary()
        elif arguments['get-etree-summary']:
            result = checker.print_etree_summary(filters=arguments['<filter>'])
        elif arguments['get-sr-summary-all']:
            result = checker.print_sr_summary_all()
        elif arguments['get-sr-summary']:
            result = checker.print_sr_summary(source=arguments['<source>'], destination=arguments['<destination>'])
        elif arguments['get-node-summary']:
            result = checker.print_node_summary()
        elif arguments['sync-status']:
            result = checker.validate_cluster()


        if not result:
            sys.exit(1)

def main():
    Shell()

if __name__ == "__main__":
    Shell()
