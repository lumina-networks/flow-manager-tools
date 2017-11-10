"""Flow Manager Topology

This module loads the topology information such as controller, switches,
and links. It provides the basic primitives to access to topology information.

"""

import threading
import logging
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
                switch_type = get_switch_type(properties)
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
            'dpid': str(hex(int(name.split(':')[1])))
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

    def validate_nodes(self, should_be_up=True, include_sr=True):
        self.load_nodes()
        result = True
        for switch in self.switches.values():
            result = False if not switch.check(should_be_up=should_be_up, validate_sr=include_sr) else result
        return result

    def load_nodes(self):
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
        self.load_links()
        result = True
        for switch in self.switches.values():
            for link in switch.links.values():
                result = False if not link.check(should_be_up=should_be_up, validate_sr=include_sr) else result

        return result

    def load_links(self):
        ctrl = self.default_ctrl
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

    def validate_openflow_elements(self, check_stats=False):
        self.load_openflow_elements()
        result = True
        for switch in self.switches.values():
            for group in switch.groups.values():
                result = False if not group.check() else result
        return result

    def load_openflow_elements(self):
        ctrl = self.default_ctrl

        #load groups
        nodes = openflow.get_config_openflow(ctrl)
        if nodes is not None and 'nodes' in nodes and 'node' in nodes['nodes']:
            for node in nodes['nodes']['node']:
                name = node['id']
                if not name.startswith('openflow:'):
                    continue
                if not self.get_switch(name):
                    self.add_switch_by_openflow_name(name)
                switch = self.get_switch(name)
                groups = node.get('flow-node-inventory:group') if 'flow-node-inventory:group' in node else node.get('group')
                if not groups or len(groups) <= 0:
                    continue
                for group in groups:
                    switch.get_group(group['group-id']).add_of_config(group)

        nodes = openflow.get_operational_openflow(ctrl)
        if nodes is not None and 'nodes' in nodes and 'node' in nodes['nodes']:
            for node in nodes['nodes']['node']:
                name = node['id']
                if not name.startswith('openflow:'):
                    continue
                if not self.get_switch(name):
                    self.add_switch_by_openflow_name(name)
                switch = self.get_switch(name)
                groups = node.get('flow-node-inventory:group') if 'flow-node-inventory:group' in node else node.get('group')
                if not groups or len(groups) <= 0:
                    continue
                for group in groups:
                    switch.get_group(group['group-id']).add_of_operational(group)


        nodes = openflow.get_fm_openflow(ctrl)
        if nodes is not None and 'nodes' in nodes and 'node' in nodes['nodes']:
            for node in nodes['nodes']['node']:
                name = node['id']
                if not name.startswith('openflow:'):
                    continue
                if not self.get_switch(name):
                    self.add_switch_by_openflow_name(name)
                switch = self.get_switch(name)
                groups = node.get('flow-node-inventory:group') if 'flow-node-inventory:group' in node else node.get('group')
                if not groups or len(groups) <= 0:
                    continue
                for group in groups:
                    switch.get_group(group['id']).add_fm(group)


        threads = []
        for switch in self.switches.values():
            t = threading.Thread(target=_load_groups_from_switch, args=(switch,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()



        # load calculated groups
        topology = openflow.get_topology(ctrl, 'flow:1:sr')
        nodes = topology.get('node') if topology else None
        if nodes is not None:
            for node in nodes:
                nodeid = node['node-id']
                brocadesr = node.get(ctrl.get_container_fm('sr:sr'))
                if brocadesr is not None:
                    self.process_calculated_groups(brocadesr)
                    self.process_calculated_flows(brocadesr.get('calculated-flows'))

        paths = openflow.get_paths(ctrl)
        if paths:
            for path in paths:
                self.process_calculated_flows(path.get('calculated-flows'))


        elines = openflow.get_elines(ctrl)
        if elines:
            for eline in elines:
                self.process_calculated_flows(eline.get('calculated-flows'))


        treepaths = openflow.get_treepaths(ctrl)
        if treepaths:
            for treepath in treepaths:
                self.process_calculated_flows(treepath.get('calculated-flows'))
                self.process_calculated_groups(treepath)

        etrees = openflow.get_etrees(ctrl)
        if etrees:
            for etree in etrees:
                self.process_calculated_flows(etree.get('calculated-flows'))
                self.process_calculated_groups(etree)

        nodes = openflow.get_path_mpls_nodes(ctrl)
        if nodes:
            self.process_calculated_flows(nodes.get('calculated-flows'))
            self.process_calculated_groups(nodes)

        nodes = openflow.get_etree_sr_nodes(ctrl)
        if nodes:
            self.process_calculated_flows(nodes.get('calculated-flows'))
            self.process_calculated_groups(nodes)

        nodes = openflow.get_eline_mpls_nodes(ctrl)
        if nodes:
            self.process_calculated_flows(nodes.get('calculated-flows'))
            self.process_calculated_groups(nodes)


    def process_calculated_groups(self, groups):
        if not groups or 'calculated-groups' not in groups:
            return
        groups = groups.get('calculated-groups')
        if not groups or 'calculated-group' not in groups:
            return
        groups = groups.get('calculated-group')
        if not groups:
            return

        for group in groups:
            if 'node-id' not in group or 'group-id' not in group:
                continue
            switch = self.get_switch(group['node-id'])
            if switch:
                switch.get_group(group['group-id']).mark_as_calculated()

    def process_calculated_flows(self, flows):
        if flows and 'calculated-flows' in flows:
            flows = flows.get('calculated-flows')
        if flows and 'calculated-flow' in flows:
            flows = flows.get('calculated-flow')
        if not flows:
            return
        #for flow in flows:
            #switch = self.get_switch(flow['node-id'])
            #if switch:
            #    switch.get_flow(flow['flow-id']).mark_as_calculated()


def _load_groups_from_switch(switch):
    groups = None
    try:
        groups = switch.get_groups()
    except:
        logging.debug("TOPOLOGY: error getting groups from %s(%s)",switch.name, switch.openflow_name)
        pass
    if groups:
        for group in groups:
            switch.get_group(group).add_switch(groups[group])
