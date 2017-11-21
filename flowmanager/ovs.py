from flowmanager.switch import Switch
from flowmanager.ssh import SSH
import subprocess


class OVS(Switch):
    def __init__(self, props, expected=False):
        Switch.__init__(self, props, expected)

        # if IP address and user is not given
        # then we need to assume OVS is running locally
        self.execute_local = not props.get('ip') and not props.get('user')

    def reboot(self, name):
        if self.execute_local:
            output = subprocess.check_output(
                "sudo ovs-vsctl get-controller {}".format(name), shell=True)
            controllersRegex = re.compile(r'(tcp:\d+\.\d+\.\d+\.\d+\:\d+)', re.IGNORECASE)
            match = controllersRegex.findall(output)
            if not match:
                print "ERROR: cannot get controllers for {}".format(name)
                return False
            controllers = ' '.join(match)
            output = subprocess.check_output("sudo ovs-vsctl del-controller {}".format(name), shell=True)
            self._delete_flows_ovs(name)
            self._delete_groups_ovs(name)
            time.sleep(5)
            output = subprocess.check_output("sudo ovs-vsctl set-controller {} {}".format(name, controllers), shell=True)
        else:
            pass  # Use Ips ports etc

    def _execute_commands_locally(self, cmds):
        for cmd in cmds:
            output = subprocess.check_output(cmd, shell=True)
        return True

    def _delete_flows_ovs(self, name):
        output = subprocess.check_output(
            "sudo ovs-ofctl del-flows {} --protocol=Openflow13".format(name), shell=True)

    def _delete_groups_ovs(self, name):
        switch = self.switches.get(name)
        if not switch:
            print "ERROR: {} switch does not exists".format(name)
            return False
        output = subprocess.check_output(
            "sudo ovs-ofctl del-groups {} --protocol=Openflow13".format(name), shell=True)

    def _get_flows_groups_from_ovs(self, node, name, prefix=None):
        if self.execute_local:
            output = subprocess.check_output(
                "sudo ovs-ofctl dump-group-stats {} --protocol=Openflow13".format(name), shell=True)
            pattern = r'group_id=(\d+)'

            regex = re.compile(r'(group_id=.*)', re.IGNORECASE)
            regexvalues = re.compile(
                r'group_id=(\d+),duration=[\d]*.[\d]*s,ref_count=[\d]*,packet_count=(\d+),byte_count=(\d+)', re.IGNORECASE)
            for linematch in regex.finditer(output):
                line = linematch.group(1)
                for match in regexvalues.finditer(line):
                    node['groups'][int(match.group(1))] = {
                        'packets': match.group(2),
                        'bytes': match.group(3)
                    }

            output = subprocess.check_output(
                "sudo ovs-ofctl dump-flows {} --protocol=Openflow13".format(name), shell=True)

            regex = re.compile(r'(cookie=.*)', re.IGNORECASE)
            regexvalues = re.compile(r'cookie=(0[xX][0-9a-fA-F]+),.*n_packets=(\d+),.*n_bytes=(\d+)', re.IGNORECASE)
            for linematch in regex.finditer(output):
                line = linematch.group(1)
                for match in regexvalues.finditer(line):
                    number = int(match.group(1), 16)
                    if prefix is None or number >> 56 == prefix:
                        node['flows'][str(number)] = {
                            'packets': match.group(2),
                            'bytes': match.group(3)
                        }
                        node['cookies'][str(number)] = node['flows'][str(number)]
                        bscid = _get_flow_bscid(number)
                        if bscid in node['bscids']:
                            print "ERROR: duplicated bsc id {} in node {}".format(bscid, name)
                        node['bscids'][int(bscid)] = number
        else:
            pass

