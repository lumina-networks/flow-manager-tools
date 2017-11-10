import re
from flowmanager.switch import Switch
from flowmanager.ssh import NoviflowSSH

class Noviflow(Switch):
    def __init__(self, props, expected=False):
        Switch.__init__(self, props, expected)


    def reboot(self):
        ssh = self._get_ssh()
        if not ssh.create_session():
            return None
        if ssh.execute_command('set status switch reboot',prompt="[all/noentries/nopipeline/none]"):
            if ssh.execute_command('noentries',prompt="(y/n)"):
                ssh.execute_command('y', prompt=None, eof=True)
                return True


    def break_gateway(self, seconds=0):
        raise Exception('break method is not implemented by this switch {}'.format(self.name))

    def delete_groups(self):
        ssh = self._get_ssh()
        if not ssh.create_session():
            return None
        if ssh.execute_command('del config group groupid all'):
            ssh.close()
            return True

    def delete_flows(self):
        raise Exception('delete flows is not implemented by this switch {}'.format(self.name))

    def get_flows(self):
        raise Exception('get flows method is not implemented by this switch {}'.format(self.name))

    def get_groups(self):
        ssh = self._get_ssh()
        if not ssh.create_session():
            return None
        text_groups = ssh.execute_command('show stats group groupid all')
        if not text_groups:
            return None

        groupIdRegex = re.compile(r'Group id:\s*(\d+)', re.IGNORECASE)
        packetCountRegex = re.compile(r'Reference count:\s*\d+\s*\S\s+Packet count:\s*(\d+)', re.IGNORECASE)
        byteCountRegex = re.compile(r'Byte count:\s*(\d+)', re.IGNORECASE)

        groups = {}
        current_group = None
        for line in text_groups.splitlines():
            match = groupIdRegex.findall(line)
            if match:
                current_group = {}
                groups[int(match[0])] = current_group
                continue
            elif current_group is None:
                continue

            match = packetCountRegex.findall(line)
            if match:
                current_group['packets']=match[0]
                if 'bytes' in current_group:
                    current_group = None
                continue

            match = byteCountRegex.findall(line)
            if match:
                current_group['bytes']=match[0]
                if 'packets' in current_group:
                    current_group = None
                continue

        ssh.close()
        return groups


    def get_controllers_role(self):
        raise Exception('get controllers method is not implemented by this switch {}'.format(self.name))

    def shutdown_port(self, port):
        raise Exception('shutdown port method is not implemented by this switch {}'.format(self.name))

    def start_port(self, port):
        raise Exception('start port method is not implemented by this switch {}'.format(self.name))

    def restart_port(self, port, seconds=0):
        raise Exception('restart port method is not implemented by this switch {}'.format(self.name))


    def _get_ssh(self):
        return NoviflowSSH(ip=self.ip, user=self.user, port=self.port, password=self.password)
