"""Flow Manager Topology

This module loads the topology information such as controller, switches,
and links. It provides the basic primitives to access to topology information.

"""

import threading
import logging
import json
import re
import random
from flowmanager.controller import Controller
from flowmanager.switch import get_switch_type
from flowmanager.switch import Switch
from flowmanager.ovs import OVS
from flowmanager.noviflow import Noviflow
from flowmanager.utils import check_mandatory_values
from flowmanager.host import Host
import flowmanager.openflow as openflow


class Topology(object):

    def __init__(self, props):
        # Disable warnings
        try:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            from requests.packages.urllib3.disable_warnings import InsecureRequestWarning
        except ImportError:
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
                # logging.info(self.switches.values())

        self.controllers = {}
        self.ctrl_name = None
        if props.get('controller'):
            for properties in props['controller']:
                new_controller = Controller(
                    properties, props.get('controller_vip'))
                self.controllers[new_controller.name] = new_controller
                if not self.ctrl_name:
                    self.ctrl_name = new_controller.name
        else:
            new_controller = Controller(
                {'name': 'c0'}, props.get('controller_vip'))
            self.controllers[new_controller.name] = new_controller
            if not self.ctrl_name:
                self.ctrl_name = new_controller.name

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

                src_host = self.get_host(
                    link['source']) if not src_switch else None
                dst_host = self.get_host(
                    link['destination']) if not dst_switch else None

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
                    src_switch.get_link(src_switch.openflow_name + ':' + str(
                        src_port), dst_switch.openflow_name + ':' + str(dst_port))
                    dst_switch.get_link(dst_switch.openflow_name + ':' + str(
                        dst_port), src_switch.openflow_name + ':' + str(src_port))

                elif src_switch and dst_host:
                    src_switch.get_link(
                        src_switch.openflow_name + ':' + str(src_port), dst_host.openflow_name)

                elif dst_switch and src_host:
                    dst_switch.get_link(
                        dst_switch.openflow_name + ':' + str(dst_port), src_host.openflow_name)

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

    def get_all_controllers(self):
        return [controller for controller in self.controllers.values()]

    def add_switch(self, switch):
        self.switches[switch.name] = switch
        self.switches_by_openflow_name[switch.openflow_name] = switch
        self.switches_by_dpid[switch.dpid] = switch

    def add_switch_by_openflow_name(self, name):
        name = str(name)
        new_switch = Switch({
            'name': name,
            'dpid': str(hex(int(name.split(':')[1])))
        })
        self.add_switch(new_switch)

    def get_switch(self, name):
        if not name:
            return None
        name = str(name)
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
        """Validates nodes against the topology"""
        # logging.info('Validating nodes...')
        self.load_nodes()  # Populates switches dict
        result = True
        for switch in self.switches.values():
            result = False if not switch.check(
                should_be_up=should_be_up, validate_sr=include_sr) else result
        if result != False:
            logging.info('All nodes detected')
        return result

    def load_nodes(self):
        """Populates switches dict by nodes"""
        # logging.info('Loading nodes...')
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
        """Validates links against the topology"""
        # logging.info('Validating links...')
        self.load_links()  # Populates switches dict
        result = True
        for switch in self.switches.values():
            for link in switch.links.values():
                if not link.check(should_be_up=should_be_up, validate_sr=include_sr):
                    result = False
                else:
                    result
        if result != False:
            logging.info('All links detected')
        return result

    def validate_cluster(self):
        result = True
        for controller in self.controllers.values():
            if controller.is_sync():
                logging.info('Controller %s is in sync', controller.name)
            else:
                logging.info('Controller %s is not in sync', controller.name)
                result = False
        logging.info('Controllers are in sync') if result else logging.error(
            'Controllers are not in sync')
        return result

    def load_links(self):
        """Populates switches dict by links"""
        logging.info('Loading links...')
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
                self.get_switch(src_node).get_link(
                    src_port).add_of_dst(dst_port)

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
                self.get_switch(src_node).get_link(
                    src_port).add_sr_dst(dst_port)

    def validate_openflow_elements(self, check_stats=False):
        self.load_openflow_elements()
        result = True
        for switch in self.switches.values():
            for group in switch.groups.values():
                result = False if not group.check() else result
            for flow in switch.flows.values():
                result = False if not flow.check() else result

        return result

    def load_openflow_elements(self):
        ctrl = self.default_ctrl

        # load groups
        nodes = openflow.get_config_openflow(ctrl)
        if nodes is not None and 'nodes' in nodes and 'node' in nodes['nodes']:
            for node in nodes['nodes']['node']:
                name = node['id']
                if not name.startswith('openflow:'):
                    continue
                if not self.get_switch(name):
                    self.add_switch_by_openflow_name(name)
                switch = self.get_switch(name)
                groups = node.get('group') if 'group' in node else node.get(
                    'flow-node-inventory:group')
                if groups:
                    for group in groups:
                        switch.get_group(
                            group['group-id']).add_of_config(group)

                tables = node.get('table') if 'table' in node else node.get(
                    'flow-node-inventory:table')
                if tables:
                    for table in tables:
                        table_id = table['id']
                        flows = table.get('flow') if 'flow' in table else table.get(
                            'flow-node-inventory:flow')
                        if flows:
                            for flow in flows:
                                switch.get_flow(table=table_id, name=flow['id'], cookie=flow.get(
                                    'cookie')).add_of_config(flow)

        nodes = openflow.get_operational_openflow(ctrl)
        if nodes is not None and 'nodes' in nodes and 'node' in nodes['nodes']:
            for node in nodes['nodes']['node']:
                name = node['id']
                if not name.startswith('openflow:'):
                    continue
                if not self.get_switch(name):
                    self.add_switch_by_openflow_name(name)
                switch = self.get_switch(name)
                groups = node.get('group') if 'group' in node else node.get(
                    'flow-node-inventory:group')
                if groups:
                    for group in groups:
                        switch.get_group(
                            group['group-id']).add_of_operational(group)

                tables = node.get('table') if 'table' in node else node.get(
                    'flow-node-inventory:table')
                if tables:
                    for table in tables:
                        table_id = table['id']
                        flows = table.get('flow') if 'flow' in table else table.get(
                            'flow-node-inventory:flow')
                        if flows:
                            for flow in flows:
                                switch.get_flow(table=table_id, name=flow['id'], cookie=flow.get(
                                    'cookie')).add_of_operational(flow)

        nodes = openflow.get_fm_openflow(ctrl)
        if nodes is not None and 'nodes' in nodes and 'node' in nodes['nodes']:
            for node in nodes['nodes']['node']:
                name = node['id']
                if not name.startswith('openflow:'):
                    continue
                if not self.get_switch(name):
                    self.add_switch_by_openflow_name(name)
                switch = self.get_switch(name)
                groups = node.get('group') if 'group' in node else node.get(
                    'flow-node-inventory:group')
                if groups:
                    for group in groups:
                        switch.get_group(group['id']).add_fm(group)

                tables = node.get('table') if 'table' in node else node.get(
                    'flow-node-inventory:table')
                if tables:
                    for table in tables:
                        table_id = table['id']
                        flows = table.get('flow') if 'flow' in table else table.get(
                            'flow-node-inventory:flow')
                        if flows:
                            for flow in flows:
                                switch.get_flow(table=table_id, name=flow['id'], cookie=flow.get(
                                    'cookie')).add_fm(flow)

        threads = []
        for switch in self.switches.values():
            t = threading.Thread(
                target=_load_openflow_from_switch, args=(switch,))
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
                    self.process_calculated(brocadesr)

        paths = openflow.get_paths(ctrl)
        if paths:
            for path in paths:
                self.process_calculated(path)

        elines = openflow.get_elines(ctrl)
        if elines:
            for eline in elines:
                self.process_calculated(eline)

        treepaths = openflow.get_treepaths(ctrl)
        if treepaths:
            for treepath in treepaths:
                self.process_calculated(treepath)

        etrees = openflow.get_etrees(ctrl)
        if etrees:
            for etree in etrees:
                self.process_calculated(etree)

        nodes = openflow.get_path_mpls_nodes(ctrl)
        if nodes:
            self.process_calculated(nodes)

        nodes = openflow.get_etree_sr_nodes(ctrl)
        if nodes:
            self.process_calculated(nodes)

        nodes = openflow.get_eline_mpls_nodes(ctrl)
        if nodes:
            self.process_calculated(nodes)

    def get_master_controller_name(self, name):
        logging.debug(self.switches_by_openflow_name)
        if name not in self.switches_by_openflow_name:
            logging.error("switch %s not found", name)
            return None
        oname = self.switches_by_openflow_name[name]
        owner = self.get_node_cluster_owner(oname)
        if not owner:
            logging.error('owner not found for switch %s', name)
            return None
        memberIdRegex = re.compile(r'member-(\d+)', re.IGNORECASE)
        match = memberIdRegex.findall(owner)
        if match:
            memberId = int(match[0])
            if (memberId <= len(self.controllers)):
                return self.controllers[memberId - 1].name
        logging.error('owner not found for switch %s', name)

    def get_node_cluster_owner(self, openflow_name):
        controller = self.controllers[self.ctrl_name]
        if openflow_name not in self.switches_by_openflow_name:
            logging.error("'%s' not detected in topology", openflow_name)
        logging.debug(openflow_name)
        resp = controller.http_get(controller.get_base_url_restconf(
        ) + '/operational/entity-owners:entity-owners/entity-type/org.opendaylight.mdsal.ServiceEntityType/entity/%2Fodl-general-entity%3Aentity%5Bodl-general-entity%3Aname%3D%27{}%27%5D'.format(openflow_name))
        logging.debug(resp.content)
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            entity = data.get('entity')
            if entity and len(entity) > 0:
                if entity[0]:
                    logging.debug(entity[0].get('owner'))
                    match = entity[0].get('owner')
                    if match:
                        memberId = int(match[-1])
                        if (memberId <= len(self.controllers)):
                            return self.controllers['c' + str(memberId)]
                    logging.error(
                        "Owner not found for switch %s", openflow_name)
        else:
            logging.error(resp.status_code)

    def get_node_cluster_owner_name(self, openflow_name):
        controller = self.controllers[self.ctrl_name]
        logging.debug(openflow_name)
        resp = controller.http_get(controller.get_base_url_restconf(
        ) + '/operational/entity-owners:entity-owners/entity-type/org.opendaylight.mdsal.ServiceEntityType/entity/%2Fodl-general-entity%3Aentity%5Bodl-general-entity%3Aname%3D%27{}%27%5D'.format(openflow_name))
        logging.debug(resp.content)
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            entity = data.get('entity')
            if entity and len(entity) > 0:
                if entity[0]:
                    logging.debug(entity[0].get('owner'))
                    return entity[0].get('owner')
                logging.error(
                    "Owner not found for switch %s", openflow_name)
        else:
            logging.error(resp.status_code)

    def validate_nodes_roles(self):
        found_error = False
        # for name in self.switches_openflow_names:
        for switch in self.switches.values():
            oname = switch.openflow_name
            roles = [i.lower() for i in switch.get_controllers_role()]
            owner = self.get_node_cluster_owner_name(oname)
            logging.debug(roles)
            if owner and roles and 'master' not in roles and 'slave' in roles:
                logging.error(
                    "%s(%s) node does not contain master in the switch. Current roles in switch%s", switch.name, oname, roles)
                found_error = True
            if not owner:
                logging.error(
                    "%s(%s) node does not contain any master in the controller. Current roles in switch%s", switch.name, oname, roles)
                found_error = True
            elif not roles:
                logging.error(
                    "%s(%s)  node does not have any role. Current roles in switch%s", switch.name, oname, roles)
                found_error = True
            else:
                memberIdRegex = re.compile(r'member-(\d+)', re.IGNORECASE)
                match = memberIdRegex.findall(owner)
                memberId = None
                if match:
                    memberId = int(match[0])
                if not memberId:
                    logging.error(
                        "%s(%s) node cannot find the member id %s. Current roles in switch %s", switch.name, oname, owner, roles)
                    found_error = True
                elif memberId > len(roles) or memberId < 0:
                    logging.error("%s(%s) node master member id %s(%s) is out of range. Current roles in switch %s",
                                  switch.name, oname, memberId, owner, roles)
                    found_error = True
                # elif roles[memberId - 1] != 'master':
                elif roles[memberId - 1] == 'slave':
                    logging.info(roles[memberId - 1])
                    logging.error("%s(%s) node, member %s(%s) is not master on the switch as expected by the controller. Current roles in switch %s",
                                  switch.name, oname, memberId, owner, roles)
                    found_error = True

        if not found_error:
            logging.info(
                "%d node roles have been detected properly", len(self.switches))
            return True
        return False

    def process_calculated(self, data):
        self.process_calculated_groups(data)

        if data and 'calculated-flow-nodes' in data:
            data = data.get('calculated-flow-nodes')
            if data and 'calculated-flow-node' in data:
                data = data.get('calculated-flow-node')
                if data:
                    for node in data:
                        self.process_calculated_flows(node)
        else:
            self.process_calculated_flows(data)

    def process_calculated_groups(self, data):
        if data and 'calculated-groups' in data:
            groups = data.get('calculated-groups')
            if groups and 'calculated-group' in groups:
                groups = groups.get('calculated-group')
                if groups:
                    for group in groups:
                        if 'node-id' not in group or 'group-id' not in group:
                            continue
                        switch = self.get_switch(group['node-id'])
                        if switch:
                            switch.get_group(
                                group['group-id']).mark_as_calculated()

    def process_calculated_flows(self, data):
        if data and 'calculated-flows' in data:
            flows = data.get('calculated-flows')
            if flows and 'calculated-flow' in flows:
                flows = flows.get('calculated-flow')
                if flows:
                    for flow in flows:
                        if 'node-id' not in flow or 'flow-name' not in flow or 'table-id' not in flow:
                            continue
                        switch = self.get_switch(flow['node-id'])
                        if switch:
                            switch.get_flow(
                                table=flow['table-id'], name=flow['flow-name']).mark_as_calculated()


def _load_openflow_from_switch(switch):
    groups = None
    groups = switch.get_groups()
    # try:

    # except:
    #     logging.error("TOPOLOGY: error getting groups from %s(%s)",
    #                   switch.name, switch.openflow_name)
    #     pass
    if groups:
        for group in groups:
            switch.get_group(group['id']).add_switch(group)

    flows = None
    try:
        flows = switch.get_flows()
    except:
        logging.error("TOPOLOGY: error getting flows from %s(%s)",
                      switch.name, switch.openflow_name)
        pass
    if flows:
        for flow in flows:
            switch.get_flow(cookie=flow['cookie']).add_switch(flow)
