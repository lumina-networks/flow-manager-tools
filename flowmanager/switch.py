"""Flow Manager Switches

This module contains the implementation of supported switches

"""
import logging
from flowmanager.utils import check_mandatory_values
from flowmanager.link import Link
from flowmanager.group import Group


def get_switch_type(props):
    return 'ovs' if not props.get('type') else props['type']


class Switch(object):

    def __init__(self, props, expected=False):
        self.found_openflow_topology = False
        self.found_sr_topology = False
        self.found_connected = False
        check_mandatory_values(props, ['name', 'dpid'])
        self.props = props
        self.expected = expected
        self.name = unicode(props['name'])
        self.dpid = str(int(props['dpid'], 16))
        self.openflow_name = "openflow:" + str(int(props['dpid'], 16))
        self.type = 'ovs' if not props.get('type') else props['type']
        self.user = 'vagrant' if not props.get('user') else props['user']
        self.password = 'vagrant' if not props.get('password') else props['password']
        self.ip = '127.0.0.1' if not props.get('ip') else props['ip']
        self.port = 22 if not props.get('port') else props['port']
        self.links = {}
        self.flows = {}
        self.groups = {}
        logging.debug('SWITCH: created switch %s(%s), type %s, ip %s, dpid %s', self.name, self.openflow_name, self.type, self.ip, props['dpid'])

    def get_link(self, source, expected_dst=None):
        source = unicode(source)
        if source not in self.links:
            self.links[source] = Link(source, expected_dst)
        return self.links[source]

    def get_group(self, groupid):
        groupid = unicode(groupid)
        if groupid not in self.groups:
            self.groups[groupid] = Group(self.openflow_name, groupid)
        return self.groups[groupid]

    def get_flow_by_fm_id(self, flow_fm_id):
        flow_fm_id = unicode(flow_fm_id)
        if flow_fm_id in self.flows:
            self.flows[flow_fm_id] = []
            self.flows[flow_fm_id].append(Flow(flow_fm_id=flow_fm_id))
        return self.flows[flow_fm_id]

    def get_flow_by_of_id(self, flow_of_id):
        flow_fm_id = unicode(flow_fm_id)
        if flow_fm_id in self.flows:
            self.flows[flow_fm_id] = []
            self.flows[flow_fm_id].append(Flow(flow_fm_id=flow_fm_id))
        return self.flows[flow_fm_id]

    def check(self, should_be_up=True, validate_sr=True):
        logging.debug("SWITCH: checking switch %s(%s) , connected %s, of topology %s, sr topology %s",self.name, self.openflow_name, self.found_connected, self.found_openflow_topology, self.found_sr_topology)
        if (not self.expected):
            print "ERROR: unexpected switch {}({}).".format(self.name, self.openflow_name)
        elif (should_be_up and not self.found_connected):
            print "ERROR: switch {}({}) not connected.".format(self.name, self.openflow_name)
        elif (not should_be_up and self.found_connected):
            print "ERROR: switch {}({}) should NOT be connected.".format(self.name, self.openflow_name)
        elif (should_be_up and not self.found_openflow_topology):
            print "ERROR: switch {}({}) not found in topology.".format(self.name, self.openflow_name)
        elif (not should_be_up and self.found_openflow_topology):
            print "ERROR: switch {}({}) should NOT be in topology.".format(self.name, self.openflow_name)
        elif (validate_sr and should_be_up and not self.found_sr_topology):
            print "ERROR: switch {}({}) not found in sr topology.".format(self.name, self.openflow_name)
        elif (validate_sr and not should_be_up and self.found_sr_topology):
            print "ERROR: switch {}({}) should NOT be in sr topology.".format(self.name, self.openflow_name)
        else:
            return True

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
        raise Exception('get groups method is not implemented by this switch {}'.format(self.name))

    def get_controllers_role(self):
        raise Exception('get controllers method is not implemented by this switch {}'.format(self.name))

    def shutdown_port(self, port):
        raise Exception('shutdown port method is not implemented by this switch {}'.format(self.name))

    def start_port(self, port):
        raise Exception('start port method is not implemented by this switch {}'.format(self.name))

    def restart_port(self, port, seconds=0):
        raise Exception('restart port method is not implemented by this switch {}'.format(self.name))
