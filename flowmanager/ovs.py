import time
import re
import subprocess
import logging
from flowmanager.switch import Switch
from flowmanager.ssh import SSH


class OVS(Switch):
    def __init__(self, props, expected=False):
        Switch.__init__(self, props, expected)

        self.type = 'ovs'
        # if IP address and user is not given
        # then we need to assume OVS is running locally
        self.execute_local = not props.get('ip') and not props.get('user')

    def reboot(self):
        if self.execute_local:
            output = subprocess.check_output(
                "sudo ovs-vsctl get-controller {}".format(self.name), shell=True)
            controllersRegex = re.compile(r'(tcp:\d+\.\d+\.\d+\.\d+\:\d+)', re.IGNORECASE)
            match = controllersRegex.findall(output)
            if not match:
                print "ERROR: cannot get controllers for {}".format(self.name)
                return False
            controllers = ' '.join(match)
            output = subprocess.check_output("sudo ovs-vsctl del-controller {}".format(self.name), shell=True)
            self.delete_flows()
            self.delete_groups()
            time.sleep(5)
            output = subprocess.check_output("sudo ovs-vsctl set-controller {} {}".format(self.name, controllers), shell=True)
        else:
            pass  # To be completed for remote OVS

    def break_gateway(self, seconds=0):
        seconds = int(seconds)
        logging.debug("INFO: trying to break connectivity to the switch %s switch", self.name)
        if 'disable_gw' not in self.props or len(self.props['disable_gw']) <= 0 or 'enable_gw' not in self.props or len(self.props['enable_gw']) <= 0:
            print "ERROR: enable or disable gw commands not found in switch {} switch".format(self.name)
            return False
        if self.execute_local:
            if not self.execute_commands(self.props['disable_gw']):
                return False
            time.sleep(seconds)
            return self.execute_commands(self.props['enable_gw'])
        else:
            pass

    def execute_commands(self, cmds):
        if self.execute_local:
            for cmd in cmds:
                output = subprocess.check_output(cmd, shell=True)
            return True
        else:
            pass

    def delete_flows(self):
        if self.execute_local:
            output = subprocess.check_output(
                "sudo ovs-ofctl del-flows {} --protocol=Openflow13".format(self.name), shell=True)
        else:
            pass  # To be completed for remote OVS

    def delete_groups(self):
        if self.execute_local:
            output = subprocess.check_output(
                "sudo ovs-ofctl del-groups {} --protocol=Openflow13".format(self.name), shell=True)
        else:
            pass

    def get_flows(self):
        if self.execute_local:
            output = subprocess.check_output("sudo ovs-ofctl dump-flows {} --protocol=Openflow13".format(self.name), shell=True)
            if not output:
                return None

            regex = re.compile(r'(cookie=.*)', re.IGNORECASE)
            regexvalues = re.compile(r'cookie=(0[xX][0-9a-fA-F]+),.*table=(\d+),.*n_packets=(\d+),.*n_bytes=(\d+)', re.IGNORECASE)

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

            return flows

        else:
            pass

    def get_groups(self):
        if self.execute_local:
            output = subprocess.check_output("sudo ovs-ofctl dump-group-stats {} --protocol=Openflow13".format(self.name), shell=True)
            if not output:
                return None
            regex = re.compile(r'(group_id=.*)', re.IGNORECASE)
            regexvalues = re.compile(r'group_id=(\d+),duration=[\d]*.[\d]*s,ref_count=[\d]*,packet_count=(\d+),byte_count=(\d+)', re.IGNORECASE)

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

        else:
            pass

    def get_controllers_role(self):
        if self.execute_local:
            controllers = subprocess.check_output("sudo ovs-vsctl  get Bridge {} controller".format(self.name), shell=True)
	    logging.debug("\n\nDEBUG: Controllers UUID received for switch %s are : %s", self.name,controllers)
            if not controllers:
                return None
            regex = re.compile(r'([0-9a-fA-F-]+)', re.IGNORECASE)
            roles = []
            for line in controllers.split(','):
                for match in regex.finditer(line):
                    if match:
                        controller = match.group(1)
                        role = subprocess.check_output("sudo ovs-vsctl  get controller {} role".format(controller), shell=True)
	                logging.debug("DEBUG: Controller with uuid %s on switch %s has role : %s", controller,self.name,role)
                        if role:
                            roles.append(role.strip('\n'))
            return roles
        else:
            pass

    def shutdown_port(self, port):
        if self.execute_local:
            shut = subprocess.check_output("sudo ovs-ofctl -O OpenFlow13 mod-port {} {} down".format(self.name, port), shell=True)
        else:
            pass

    def start_port(self, port):
        if self.execute_local:
            start = subprocess.check_output("sudo ovs-ofctl -O OpenFlow13 mod-port {} {} up".format(self.name, port), shell=True)
        else:
            pass

    def restart_port(self, port, seconds=0):
        if self.execute_local:
            self.shutdown_port(port)
            time.sleep(seconds)
            self.start_port(port)
        else:
            pass

    def list_ports(self):
        if self.execute_local:
            list = subprocess.check_output("sudo ovs-vsctl list-ports {}".format(self.name), shell=True)
            print list
        else:
            pass

    def port_status(self, port):
        if self.execute_local:
            status = subprocess.check_output("sudo ovs-ofctl -O OpenFlow13 dump-ports-desc {} {}".format(self.name, port), shell=True)
            print status
        else:
            pass

    def _get_ssh(self):
        raise Exception('_get_ssh method is not implemented by this switch {}'.format(self.name))

