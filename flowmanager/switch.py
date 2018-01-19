"""Flow Manager Switches

This module contains the implementation of supported switches

"""
import logging
from flowmanager.utils import check_mandatory_values
from flowmanager.link import Link
from flowmanager.group import Group
from flowmanager.flow import Flow
from flowmanager.flow import get_id as get_flow_id


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
        self.type = 'unknown' if not props.get('type') else props['type']
        self.user = None if not props.get('user') else props['user']
        self.password = None if not props.get(
            'password') else props['password']
        self.ip = None if not props.get('ip') else props['ip']
        self.port = 22 if not props.get('port') else props['port']
        self.links = {}
        self.flows = {}
        self.flows_by_name = {}
        self.flows_by_id = {}
        self.groups = {}
        logging.debug('SWITCH: created switch %s(%s), type %s, ip %s, dpid %s',
                      self.name, self.openflow_name, self.type, self.ip, props['dpid'])

    def get_link(self, source, expected_dst=None):
        source = unicode(source)
        if source not in self.links:
            self.links[source] = Link(source, expected_dst)
        return self.links[source]

    def get_group(self, groupid):
        groupid = unicode(groupid)
        if groupid not in self.groups:
            self.groups[groupid] = Group(
                node=self.name, node_of_name=self.openflow_name, groupid=groupid)
        return self.groups[groupid]

    def get_flow(self, table=None, name=None, cookie=None):
        cookie = str(cookie) if cookie is not None else None
        name = str(name) if name is not None else None
        table = str(table) if table is not None else None

        if not cookie and (not table or not name):
            raise Exception('cookie or table and name is mandatory')

        flow_name = "table/{}/name/{}".format(
            table, name) if table is not None and name is not None else None
        flow_fm_id = str(get_flow_id(cookie)) if cookie is not None else None

        current_flow = self.flows_by_name[flow_name] if flow_name and flow_name in self.flows_by_name else None
        current_flow = self.flows_by_id[flow_fm_id] if not current_flow and flow_fm_id and flow_fm_id in self.flows_by_id else current_flow

        if not current_flow:
            current_flow = Flow(
                node=self.name, node_of_name=self.openflow_name, cookie=cookie, table=table, name=name)
            if flow_name:
                self.flows_by_name[flow_name] = current_flow
            if flow_fm_id:
                self.flows_by_id[flow_fm_id] = current_flow
            if flow_name:
                self.flows[flow_name] = current_flow
            else:
                self.flows[flow_fm_id] = current_flow

        return current_flow

    def check(self, should_be_up=True, validate_sr=True):
        logging.debug("SWITCH: checking switch %s(%s) , connected %s, of topology %s, sr topology %s", self.name,
                      self.openflow_name, self.found_connected, self.found_openflow_topology, self.found_sr_topology)
        if (not self.expected):
            logging.error("unexpected switch %s(%s).",
                          self.name, self.openflow_name)
        elif (should_be_up and not self.found_connected):
            logging.error("switch %s(%s) not connected.",
                          self.name, self.openflow_name)
        elif (not should_be_up and self.found_connected):
            logging.error("switch %s(%s) should NOT be connected.",
                          self.name, self.openflow_name)
        elif (should_be_up and not self.found_openflow_topology):
            logging.error("switch %s(%s) not found in topology.",
                          self.name, self.openflow_name)
        elif (not should_be_up and self.found_openflow_topology):
            logging.error("switch %s(%s) should NOT be in topology.",
                          self.name, self.openflow_name)
        elif (validate_sr and should_be_up and not self.found_sr_topology):
            logging.error("switch %s(%s) not found in sr topology.",
                          self.name, self.openflow_name)
        elif (validate_sr and not should_be_up and self.found_sr_topology):
            logging.error("switch %s(%s) should NOT be in sr topology.",
                          self.name, self.openflow_name)
        else:
            return True

    def reboot(self):
        raise Exception(
            'reboot method is not implemented by this switch {}'.format(self.name))

    def break_gateway(self, seconds=0):
        raise Exception(
            'break method is not implemented by this switch {}'.format(self.name))

    def break_controller_switch(self, controller_name, seconds=30):
        raise Exception(
            'break method is not implemented by this switch {}'.format(self.name))

    def delete_groups(self):
        raise Exception(
            'delete groups method is not implemented by this switch {}'.format(self.name))

    def delete_flows(self):
        raise Exception(
            'delete flows is not implemented by this switch {}'.format(self.name))

    def get_flows(self):
        raise Exception(
            'get flows method is not implemented by this switch {}'.format(self.name))

    def get_flow_stats(self):
        raise Exception(
            'get flows method is not implemented by this switch {}'.format(self.name))

    def get_groups(self):
        raise Exception(
            'get groups method is not implemented by this switch {}'.format(self.name))

    def get_group_stats(self):
        raise Exception(
            'get flows method is not implemented by this switch {}'.format(self.name))

    def get_controllers_role(self):
        raise Exception(
            'get controllers method is not implemented by this switch {}'.format(self.name))

    def shutdown_port(self, port):
        raise Exception(
            'shutdown port method is not implemented by this switch {}'.format(self.name))

    def start_port(self, port):
        raise Exception(
            'start port method is not implemented by this switch {}'.format(self.name))

    def restart_port(self, port, seconds=0):
        raise Exception(
            'restart port method is not implemented by this switch {}'.format(self.name))
