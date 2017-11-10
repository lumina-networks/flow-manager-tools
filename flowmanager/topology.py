"""Flow Manager Topology

This module loads the topology information such as controller, switches,
and links. It provides the basic primitives to access to topology information.

"""

import random
from flowmanager.controller import Controller
from flowmanager.switch import get_switch_type
from flowmanager.switch import Switch
from flowmanager.ovs import OVS
from flowmanager.noviflow import Noviflow
from flowmanager.utils import check_mandatory_values
import flowmanager.openflow as openflow

class Topology(object):

    def __init__(self, props):
        # Disable warnings
        try:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except:
            pass

        self.hosts = {}
        self.hosts_by_openflow_name = {}
        if props.get('host'):
            for properties in props['host']:
                new_host = Host(properties, True)
                self.add_host(new_host)

        self.switches = {}
        self.switches_by_openflow_name = {}
        self.switches_by_dpid = {}
        if props.get('switch'):
            for properties in props['switch']:
                switch_type = get_switch_type(props)
                if switch_type and switch_type == 'noviflow':
                    new_switch = Noviflow(properties, True)
                else:
                    new_switch = OVS(properties, True)

                self.add_switch(new_switch)

        self.controllers = {}
        if props.get('controller'):
            for properties in props['controller']:
                new_controller = Controller(properties, props.get('controller_vip'))
                self.controllers[new_controller.name] = new_controller
        else:
            new_controller = Controller({'name': 'c0'}, props.get('controller_vip'))
            self.controllers[new_controller.name] = new_controller

        self.default_ctrl = self.get_random_controller()

        self.links = {}
        if props.get('link'):
            ports = {}
            for link in props['link']:
                check_mandatory_values(link, ['source', 'destination'])

                src_switch = self.get_switch(link['source'])
                src_name = src_switch.openflow_name if src_switch else None

                dst_switch = self.get_switch(link['destination'])
                dst_name = dst_switch.openflow_name if dst_switch else None

                src_host = self.get_host(link['source']) if not src_switch else None
                dst_host = self.get_host(link['destination']) if not dst_switch else None

                source = None
                if src_switch:
                    src_port = link.get('source_port')
                    if not src_port:
                        if src_name not in ports:
                            ports[src_name] = 1
                        link['source_port'] = ports[src_name]
                        src_port = ports[src_name]
                        ports[src_name] = ports[src_name] + 1

                destination = None
                if dst_switch:
                    dst_port = link.get('destination_port')
                    if not dst_port:
                        if dst_name not in ports:
                            ports[dst_name] = 1
                        link['destination_port'] = ports[dst_name]
                        dst_port = ports[dst_name]
                        ports[dst_name] = ports[dst_name] + 1

                # add the links
                if src_switch and dst_switch:
                    src_switch.get_link(src_switch.openflow_name + ':' + str(src_port), dst_switch.openflow_name + ':' + str(dst_port))
                    dst_switch.get_link(dst_switch.openflow_name + ':' + str(dst_port), src_switch.openflow_name + ':' + str(src_port))

                elif src_switch and dst_host:
                    src_switch.get_link(src_switch.openflow_name + ':' + str(src_port), dst_host.openflow_name)

                elif dst_switch and src_host:
                    dst_switch.get_link(dst_switch.openflow_name + ':' + str(dst_port), src_host.openflow_name)

    def add_host(self, host):
        self.hosts[host.name] = host
        self.hosts_by_openflow_name[host.openflow_name] = host

    def get_host(self, name):
        if name and name in self.hosts:
            return self.hosts[name]
        if name in self.hosts_by_openflow_name:
            return self.hosts_by_openflow_name[name]
        if 'host:' + name in self.hosts_by_openflow_name:
            return self.hosts_by_openflow_name['host:' + name]

    def get_random_host(self):
        return self.get_host(self.get_random_host_name())

    def get_random_host_name(self):
        return random.choice(self.hosts.keys())

    def get_controller(self, name):
        if name and name in self.controllers:
            return self.controllers[name]

    def get_random_controller(self):
        return self.get_controller(self.get_random_controller_name())

    def get_random_controller_name(self):
        return random.choice(self.controllers.keys())

    def add_switch(self, switch):
        self.switches[switch.name] = switch
        self.switches_by_openflow_name[switch.openflow_name] = switch
        self.switches_by_dpid[switch.dpid] = switch

    def add_switch_by_openflow_name(self, name):
        name = unicode(name)
        new_switch = Switch({
            'name': name,
            'dpid': str(hex(name.split(':')[1]))
        })
        self.add_switch(new_switch)

    def get_switch(self, name):
        if not name:
            return None
        name = unicode(name)
        if name in self.switches:
            return self.switches[name]
        if name in self.switches_by_openflow_name:
            return self.switches_by_openflow_name[name]
        if 'openflow:' + name in self.switches_by_openflow_name:
            return self.switches_by_openflow_name['openflow:' + name]
        if name in self.switches_by_dpid:
            return self.switches_by_dpid[name]

    def get_random_switch(self):
        return self.get_switch(self.get_random_switch_name())

    def get_random_switch_name(self):
        return random.choice(self.switches.keys())

    def reconciliate_nodes(self, should_be_up=True, include_sr=True):
        ctrl = self.default_ctrl
        nodes = openflow.get_topology_nodes(ctrl, 'flow:1')
        if nodes:
            for node in nodes:
                if not self.get_switch(node):
                    self.add_switch_by_openflow_name(node)
                self.get_switch(node).found_openflow_topology = True

        nodes = openflow.get_topology_nodes(ctrl, 'flow:1:sr')
        if nodes:
            for node in nodes:
                if not self.get_switch(node):
                    self.add_switch_by_openflow_name(node)
                self.get_switch(node).found_sr_topology = True

        nodes = openflow.get_openflow_connected_nodes(ctrl)
        if nodes:
            for node in nodes:
                if not self.get_switch(node):
                    self.add_switch_by_openflow_name(node)
                self.get_switch(node).found_connected = True

    def validate_links(self, should_be_up=True, include_sr=True):
        ctrl = self.default_ctrl
        print self.switches
        links = openflow.get_topology_links(ctrl, 'flow:1')
        if links:
            for name in links:
                link = links[name]
                src_node = link['source']['source-node']
                src_port = link['source']['source-tp']
                dst_node = link['destination']['dest-node']
                dst_port = link['destination']['dest-tp']
                if not self.get_switch(src_node):
                    self.add_switch_by_openflow_name(src_node)
                self.get_switch(src_node).get_link(src_port).add_of_dst(dst_port)

        links = openflow.get_topology_links(ctrl, 'flow:1:sr')
        if links:
            for name in links:
                link = links[name]
                src_node = link['source']['source-node']
                src_port = link['source']['source-tp']
                dst_node = link['destination']['dest-node']
                dst_port = link['destination']['dest-tp']
                if not self.get_switch(src_node):
                    self.add_switch_by_openflow_name(src_node)
                self.get_switch(src_node).get_link(src_port).add_sr_dst(dst_port)

        result = False
        for switch in self.switches.values():
            for link in switch.links.values():
                result = True if link.check(should_be_up=should_be_up, validate_sr=include_sr) else result

        return result
