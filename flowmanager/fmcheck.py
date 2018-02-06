"""Flow Manager Testing Tools

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
  fmcheck get-flow-stats-all [-d] [--topology=FILE]
  fmcheck get-flow-stats <filter>... [-d] [--topology=FILE]
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

"""
from __future__ import print_function
import os
import sys
import yaml
import logging
import coloredlogs
from flowmanager.topology import Topology
import flowmanager.openflow
from docopt.docopt import docopt


class Shell(object):

    def __init__(self):
        arguments = docopt(__doc__, version='Flow Manager Testing Tools 1.1')

        if arguments['--debug']:
            logging.getLogger().setLevel(logging.DEBUG)
            coloredlogs.install(level='DEBUG')
            # print(arguments)
        else:
            logging.getLogger().setLevel(logging.INFO)
            coloredlogs.install(level='INFO')

        if arguments['--topology']:
            file = arguments['--topology']
            if not (os.path.isfile(file)):
                raise Exception(
                    "given topology file {} not found".format(file))
        else:
            file = 'prod-topo.yml' if os.path.isfile('prod-topo.yml') else None
            file = 'mn-topo.yml' if not file and os.path.isfile(
                'mn-topo.yml') else file
            file = 'fm-topo.yml' if not file and os.path.isfile(
                'fm-topo.yml') else file
            if not file:
                raise Exception('default topology file not found')

        props = None
        if (os.path.isfile(file)):
            with open(file, 'r') as f:
                props = yaml.load(f)

        if props is None:
            logging.error("yml topology file %s not loaded", file)
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

        result = None
        topology = Topology(props)
        if arguments['links']:
            should_be_up = True if not arguments['--stopped'] else False
            include_sr = True if arguments['--segementrouting'] else False
            result = topology.validate_links(
                should_be_up=should_be_up, include_sr=include_sr)

        elif arguments['nodes']:
            should_be_up = True if not arguments['--stopped'] else False
            include_sr = True if arguments['--segementrouting'] else False
            result = topology.validate_nodes(
                should_be_up=should_be_up, include_sr=include_sr)

        elif arguments['roles']:
            result = topology.validate_nodes_roles()

        elif arguments['flows']:
            result = topology.validate_openflow_elements(
                check_stats=True if arguments['--check-stats'] else False)

        elif arguments['sync-status']:
            result = topology.validate_cluster()
        # Reboot Commands
        elif arguments['reboot-random-controller']:
            ctrl = topology.get_random_controller()
            if not ctrl:
                result = False
                logging.error("controller not found")
            else:
                result = topology.get_random_controller().reboot()

        elif arguments['reboot-controller']:
            ctrl = topology.get_controller(arguments['<name>'])
            if not ctrl:
                result = False
                logging.error("controller %s not found", arguments['<name>'])
            else:
                result = topology.get_controller(arguments['<name>']).reboot()

        elif arguments['reboot-controller-by-switch']:
            result = topology.get_node_cluster_owner(
                arguments['<name>']).reboot()

        elif arguments['reboot-controller-by-random-switch']:
            result = topology.get_node_cluster_owner(
                topology.get_random_switch().openflow_name).reboot()

        elif arguments['reboot-random-switch']:
            switch = topology.get_random_switch()
            if switch:
                result = switch.reboot()
            else:
                logging.error("random switch not found")

        elif arguments['reboot-switch']:
            switch = topology.get_switch(arguments['<name>'])
            if switch:
                result = switch.reboot()
            else:
                logging.error("switch %s not found", arguments['<name>'])

        elif arguments['reboot-controller-vm']:
            ctrl = topology.get_controller(arguments['<name>'])
            if not ctrl:
                result = False
                logging.error("controller %s not found", arguments['<name>'])
            else:
                result = topology.get_controller(
                    arguments['<name>']).reboot_vm()

        elif arguments['reboot-random-controller-vm']:
            ctrl = topology.get_random_controller()
            if not ctrl:
                result = False
                logging.error("controller not found")
            else:
                result = topology.get_random_controller().reboot_vm()

        # Break Commands
        elif arguments['break-gw-switch']:
            result = topology.get_switch(arguments['<name>']).break_gateway(
                seconds=arguments['<seconds>'])

        elif arguments['break-random-gw-switch']:
            result = topology.get_random_switch().break_gateway(
                seconds=arguments['<seconds>'])

        elif arguments['break-ctrl-switch']:
            result = topology.get_switch(arguments['<switch_name>']).break_controller_switch(
                controller_name=arguments['<controller_name>'], seconds=arguments['<seconds>'])

        elif arguments['break-random-ctrl-switch']:
            result = topology.get_random_switch().break_controller_switch(
                controller_name=arguments['<controller_name>'], seconds=arguments['<seconds>'])

        # Isolate Commands
        elif arguments['isolate-ctrl']:
            result = topology.get_controller(
                arguments['<controller_name>']).isolate(seconds=arguments['<seconds>'])

        elif arguments['isolate-random-ctrl']:
            result = topology.get_random_controller().isolate(
                seconds=arguments['<seconds>'])

        elif arguments['isolate-ctrl-switch']:
            result = topology.get_node_cluster_owner(
                arguments['<switch_name>']).isolate(seconds=arguments['<seconds>'])

        elif arguments['isolate-random-ctrl-switch']:
            result = topology.get_node_cluster_owner(
                topology.get_random_switch_name()).isolate(seconds=arguments['<seconds>'])

        # Delete commands
        elif arguments['delete-random-groups']:
            switch = topology.get_random_switch()
            if switch:
                result = switch.delete_groups()
            else:
                logging.error("random switch not found")

        elif arguments['delete-groups']:
            switch = topology.get_switch(arguments['<name>'])
            if switch:
                result = switch.delete_groups()
            else:
                logging.error("switch %s not found", arguments['<name>'])

        elif arguments['delete-random-flows']:
            result = topology.get_random_switch().delete_flows()

        elif arguments['delete-flows']:
            result = topology.get_switch(arguments['<name>']).delete_flows()

        # Get flow stats
        elif arguments['get-flow-stats-all']:
            result = topology.get_random_controller().get_flow_stats()

        elif arguments['get-flow-stats']:
            result = topology.get_random_controller().get_flow_stats(
                filters=arguments['<filter>'])

        elif arguments['get-flow-node-stats-all']:
            result = topology.get_node_cluster_owner(
                arguments['<node>']).get_flow_stats(node_name=arguments['<node>'])

        elif arguments['get-flow-node-stats']:
            result = topology.get_node_cluster_owner(
                arguments['<node>']).get_flow_stats(node_name=arguments['<node>'], filters=arguments['<filter>'])

        # Get group stats
        elif arguments['get-group-stats-all']:
            result = topology.get_random_controller().get_group_stats()

        elif arguments['get-group-stats']:
            result = topology.get_random_controller().get_group_stats(
                filters=arguments['<filter>'])

        elif arguments['get-group-node-stats-all']:
            result = topology.get_node_cluster_owner(
                openflow_name=arguments['<node>']).get_group_stats(node_name=arguments['<node>'])

        elif arguments['get-group-node-stats']:
            result = topology.get_node_cluster_owner(
                openflow_name=arguments['<node>']).get_group_stats(filters=arguments['<filter>'], node_name=arguments['<node>'])

        # Get Eline stats
        elif arguments['get-eline-stats-all']:
            result = topology.get_random_controller().get_eline_stats()
        elif arguments['get-eline-stats']:
            result = topology.get_random_controller().get_eline_stats(
                filters=arguments['<filter>'])
        elif arguments['get-eline-summary-all']:
            result = topology.get_random_controller().get_eline_summary()
        elif arguments['get-eline-summary']:
            result = topology.get_random_controller().get_eline_summary(
                filters=arguments['<filter>'])

        # Get Etree stats
        elif arguments['get-etree-stats-all']:
            result = flowmanager.openflow.get_etrees(
                topology.get_random_controller())
            # result = topology.get_random_controller().get_etree_stats()
        elif arguments['get-etree-stats']:
            result = topology.get_random_controller().get_etree_stats(
                filters=arguments['<filter>'])
        elif arguments['get-etree-summary-all']:
            result = topology.get_random_controller().get_etree_summary()
        elif arguments['get-etree-summary']:
            result = topology.get_random_controller().get_etree_summary(
                filters=arguments['<filter>'])

        # Get Segment Routing info
        elif arguments['get-sr-summary-all']:
            result = topology.get_random_controller().get_sr_summary_all(
                topology.switches_by_openflow_name)
        elif arguments['get-sr-summary']:
            result = topology.get_random_controller().get_sr_summary(
                source=arguments['<source>'], destination=arguments['<destination>'])
        # Get Node Summary
        elif arguments['get-node-summary']:
            result = topology.get_random_controller().get_node_summary(
                topology.switches_by_openflow_name)

        if not result:
            sys.exit(1)


def main():
    Shell()


if __name__ == "__main__":
    Shell()
