import time
import re
import subprocess
import logging
from flowmanager.switch import Switch
from flowmanager.ssh import SSH


class OVS(Switch):

    """

    Inherits from Switch and Implements Open vSwitch specific methods

    """

    def __init__(self, props, expected=False):
        Switch.__init__(self, props, expected)

        self.type = 'ovs'
        # if IP address and user is not given
        # then we need to assume OVS is running locally
        self.execute_local = not props.get('ip') and not props.get('user')
        # self.ssh = None if not self.execute_local else SSH(
        #     ip=self.ip, user=self.user, port=self.port, password=self.password)
        self.ssh = None if self.execute_local else SSH(ip=self.ip, user=self.user,
                                                       port=self.port, password=self.password)

    def _execute_commands(self, commands):
        for command in commands:
            if not self._execute_command(command):
                return False
        return True

    def _execute_command(self, command):
        if not self.ssh:
            try:
                return subprocess.check_output(command, shell=True)
            except Exception, msg:
                logging.error(msg)
        else:
            return self.ssh.execute_single_command(command)
            # return self.ssh.execute_command(command)

    def reboot(self):
        raise NotImplementedError
        # output = self._execute_command(
        #     "sudo ovs-vsctl get-controller {}".format(self.name))
        # controllersRegex = re.compile(
        #     r'(tcp:\d+\.\d+\.\d+\.\d+\:\d+)', re.IGNORECASE)
        # match = controllersRegex.findall(output)
        # if not match:
        #     logging.error("cannot get controllers for %s", self.name)
        #     return False
        #     controllers = ' '.join(match)
        #     self._execute_command(
        #         "sudo ovs-vsctl del-controller {}".format(self.name))
        #     self.delete_flows()
        #     self.delete_groups()
        #     time.sleep(5)
        #     self._execute_command(
        #         "sudo ovs-vsctl set-controller {} {}".format(self.name, controllers), shell=True)
        #     return True

    def break_gateway(self, seconds=0):
        seconds = int(seconds)
        logging.debug(
            "INFO: trying to break connectivity to the switch %s switch", self.name)
        if 'disable_gw' not in self.props or len(self.props['disable_gw']) <= 0 or 'enable_gw' not in self.props or len(self.props['enable_gw']) <= 0:
            logging.error(
                "enable or disable gw commands not found in switch %s switch", self.name)
            return False
        if not self._execute_commands(self.props['disable_gw']):
            return False
        time.sleep(seconds)
        return self._execute_commands(self.props['enable_gw'])

    def delete_flows(self):
        return self._execute_command("sudo ovs-ofctl del-flows {} --protocol=Openflow13".format(self.name))

    def delete_groups(self):
        return self._execute_command("sudo ovs-ofctl del-groups {} --protocol=Openflow13".format(self.name))

    def get_flows(self):
        output = self._execute_command(
            "sudo ovs-ofctl dump-flows {} --protocol=Openflow13".format(self.name))
        if not output:
            return None

        regex = re.compile(r'(cookie=.*)', re.IGNORECASE)
        regexvalues = re.compile(
            r'cookie=(0[xX][0-9a-fA-F]+),.*table=(\d+),.*n_packets=(\d+),.*n_bytes=(\d+)', re.IGNORECASE)

        flows = []
        flowid = None
        for linematch in regex.finditer(output):
            line = linematch.group(1)
            for match in regexvalues.finditer(line):
                flow = {}
                flow['id'] = flowid
                flow['cookie'] = int(match.group(1), 16)
                flow['table'] = match.group(2)
                flow['packets'] = match.group(3)
                flow['bytes'] = match.group(4)
                flows.append(flow)
        logging.debug(flows)
        return flows

    def get_groups(self):
        output = self._execute_command(
            "sudo ovs-ofctl dump-group-stats {} --protocol=Openflow13".format(self.name))
        if not output:
            return None
        regex = re.compile(r'(group_id=.*)', re.IGNORECASE)
        regexvalues = re.compile(
            r'group_id=(\d+),duration=[\d]*.[\d]*s,ref_count=[\d]*,packet_count=(\d+),byte_count=(\d+)', re.IGNORECASE)

        groups = []
        for linematch in regex.finditer(output):
            line = linematch.group(1)
            for match in regexvalues.finditer(line):
                group = {}
                group['id'] = match.group(1)
                group['packets'] = match.group(2)
                group['bytes'] = match.group(3)
                groups.append(group)

        return groups

    def get_controllers_role(self):
        logging.info(
            'OVS switches roles not implemented, default set to equal')
        return 'equal'

        # controllers = self._execute_command(
        #     "sudo ovs-vsctl get Bridge {} controller".format(self.name))
        # logging.debug(
        #     "DEBUG: Controllers UUID received for switch %s are : %s", self.name, controllers)
        # if not controllers:
        #     return None
        # regex = re.compile(r'([0-9a-fA-F-]+)', re.IGNORECASE)
        # roles = []
        # for line in controllers.split(','):
        #     for match in regex.finditer(line):
        #         if match:
        #             controller = match.group(1)
        #             role = self._execute_command(
        #                 "sudo ovs-vsctl  get controller {} role".format(controller))
        #             logging.debug(
        #                 "DEBUG: Controller with uuid %s on switch %s has role : %s", controller, self.name, role)
        #             if role:
        #                 roles.append(role.strip('\n'))
        # return roles

    def shutdown_port(self, port):
        shut = self._execute_command(
            "sudo ovs-ofctl -O OpenFlow13 mod-port {} {} down".format(self.name, port))

    def start_port(self, port):
        start = self._execute_command(
            "sudo ovs-ofctl -O OpenFlow13 mod-port {} {} up".format(self.name, port))

    def restart_port(self, port, seconds=0):
        if not self.shutdown_port(port):
            return False
        time.sleep(seconds)
        return self.start_port(port)

    def list_ports(self):
        list = self._execute_command(
            "sudo ovs-vsctl list-ports {}".format(self.name))
        logging.info(list)

    def port_status(self, port):
        status = self._execute_command(
            "sudo ovs-ofctl -O OpenFlow13 dump-ports-desc {} {}".format(self.name, port))
        logging.info(status)
