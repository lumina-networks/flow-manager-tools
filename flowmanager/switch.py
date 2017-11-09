"""Flow Manager Switches

This module contains the implementation of supported switches

"""

def get_switch_type(props):
    return 'ovs' if not props.get('type') else props['type']

class Switch(object):

    def __init__(self, props):
        utils.check_mandatory_values(props, ['name', 'dpid'])
        self.props = props
        self.name = props['name']
        self.dpid = str(int(props['dpid'], 16))
        self.openflow_name = "openflow:" + str(int(props['dpid'], 16))
        self.type = 'ovs' if not props.get('type') else props['type']
        self.user = 'vagrant' if not props.get('user') else props['user']
        self.password = 'vagrant' if not props.get('password') else props['password']
        self.ip = '127.0.0.1' if not props.get('ip') else props['ip']
        self.port = 22 if not props.get('port') else props['port']
        self.links_by_port = {}
        self.links_by_openflow_port = {}
        self.destination_switches = {}
        self.destination_hosts = {}

    def add_link_to_switch(self, source_port, destination_switch, destination_port):
        self.links_by_port[str(source_port)] = destination_switch.openflow_name + ':' + destination_port
        self.links_by_openflow_port[self.openflow_name + ':' + str(source_port)] = destination_switch.openflow_name + ':' + destination_port
        self.destination_switches[str(source_port)] = destination_switch

    def add_link_to_host(self, source_port, host):
        self.links_by_port[str(source_port)] = host.openflow_name
        self.links_by_openflow_port[self.openflow_name + ':' + str(source_port)] = host.openflow_name
        self.destination_hosts[str(source_port)] = host

    def reboot(self):
        raise Exception('reboot method is not implemented by this switch {}'.format(self.name))

    def break_gateway(self, seconds=0):
        raise Exception('break method is not implemented by this switch {}'.format(self.name))

    def delete_groups(self):
        raise Exception('delete groups method is not implemented by this switch {}'.format(self.name))

    def delete_flows(self):
        raise Exception('delete flows is not implemented by this switch {}'.format(self.name))

    def get_flows(self):
        raise Exception('get flows method is not implemented by this switch {}'.format(self.name))

    def get_groups(self):
        raise Exception('get flows method is not implemented by this switch {}'.format(self.name))

    def get_controllers_role(self):
        raise Exception('get controllers method is not implemented by this switch {}'.format(self.name))

    def shutdown_port(self, port):
        raise Exception('shutdown port method is not implemented by this switch {}'.format(self.name))

    def start_port(self, port):
        raise Exception('start port method is not implemented by this switch {}'.format(self.name))

    def restart_port(self, port, seconds=0):
        raise Exception('restart port method is not implemented by this switch {}'.format(self.name))
