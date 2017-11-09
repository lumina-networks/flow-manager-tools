"""Flow Manager Switches

This module contains the implementation of supported switches

"""

def get_switch_type(props):
    return 'ovs' if not props.get('type') else props['type']

class Switch(object):

    def __init__(self, props, expected=False):
        self.found_openflow_topology = False
        self.found_sr_topology = False
        self.found_connected = False
        utils.check_mandatory_values(props, ['name', 'dpid'])
        self.props = props
        self.expected = expected
        self.name = props['name']
        self.dpid = str(int(props['dpid'], 16))
        self.openflow_name = "openflow:" + str(int(props['dpid'], 16))
        self.type = 'ovs' if not props.get('type') else props['type']
        self.user = 'vagrant' if not props.get('user') else props['user']
        self.password = 'vagrant' if not props.get('password') else props['password']
        self.ip = '127.0.0.1' if not props.get('ip') else props['ip']
        self.port = 22 if not props.get('port') else props['port']
        self.links = {}

    def get_link(self, source, expected_dst=None):
        if source not in links:
            links[source] = Link(source, expected_dst)
        return links[source]

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
