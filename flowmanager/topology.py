"""Flow Manager Topology

This module loads the topology information such as controller, switches,
and links. It provides the basic primitives to access to topology information.

"""

import random

class Topo(object):

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
                new_host = Host(properties)
                self.hosts[new_host.name] = new_host
                self.hosts_by_openflow_name[new_host.openflow_name] = new_host

        self.switches = {}
        self.switches_by_openflow_name = {}
        self.switches_by_dpid = {}
        if props.get('switch'):
            for properties in props['switch']:
                switch_type = switch.get_switch_type(props)
                if switch_type and switch_type == 'noviflow':
                    new_switch = Noviflow(properties)
                else:
                    new_switch = OVS(properties)

                self.switches[new_switch.name] = new_switch
                self.switches_by_openflow_name[new_switch.openflow_name] = new_switch
                self.switches_by_dpid[new_switch.dpid] = new_switch

        self.controllers = {}
        if props.get('controller'):
            for properties in props['controller']:
                new_controller = Controller(properties, props.get('controller_vip'))
                self.controllers[new_controller.name] = new_controller
        else:
            new_controller = Controller({'name': 'c0'}, props.get('controller_vip'))
            self.controllers[new_controller.name] = new_controller

        self.links = {}
        if props.get('link'):
            ports = {}
            for link in props['link']:
                utils.check_mandatory_values(link, ['source', 'destination'])

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
                if dst_name in self.switches:
                    dst_port = link.get('destination_port')
                    if not dst_port:
                        if dst_name not in ports:
                            ports[dst_name] = 1
                        link['destination_port'] = ports[dst_name]
                        dst_port = ports[dst_name]
                        ports[dst_name] = ports[dst_name] + 1

                # add the links
                if src_switch and dst_switch:
                    src_switch.add_link_to_switch(src_port, dst_switch, dst_port)
                    dst_switch.add_link_to_switch(dst_port, src_switch, src_port)

                elif src_switch and dst_host:
                    src_switch.add_link_to_host(src_port, dst_host)

                elif dst_switch and src_host:
                    dst_switch.add_link_to_host(dst_port, src_host)

        def get_host(self, name):
            if name and name in self.hosts:
                return self.hosts[name]
            if name in self.hosts_by_openflow_name:
                return self.hosts_by_openflow_name[name]
            if 'host:' + name in self.hosts_by_openflow_name:
                return self.hosts_by_openflow_name['host:' + name]

        def get_random_host(self):
            return get_host(self.get_random_host_name())

        def get_random_host_name(self):
            return random.choice(self.hosts.keys())

        def get_controller(self, name):
            if name and name in self.controllers:
                return self.controllers[name]

        def get_random_controller(self):
            return get_controller(self.get_random_controller_name())

        def get_random_controller_name(self):
            return random.choice(self.controllers.keys())

        def get_switch(self, name):
            if not name:
                return None
            if name in self.switches:
                return self.switches[name]
            if name in self.switches_openflow_names:
                return self.switches_openflow_names[name]
            if 'openflow:' + name in self.switches_openflow_names:
                return self.switches_openflow_names['openflow:' + name]
            if name in self.switches_by_dpid:
                return self.switches_by_dpid[name]

        def get_random_switch(self):
            return self.get_switch(self.get_random_switch_name())

        def get_random_switch_name(self):
            return random.choice(self.switches.keys())

        def get_links(self, filter_hosts=True):
            links = {}
            for switch in self.switches.itervalues():
                for source in switch.links_by_openflow_port:
                    if not filter_hosts or (not source.startswith('host:') and not switch.links_by_openflow_port[source].startswith('host:')):
                        links[source] = switch.links_by_openflow_port[source]
