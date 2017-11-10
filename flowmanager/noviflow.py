from flowmanager.switch import Switch
from flowmanager.ssh import NoviflowSSH

class Noviflow(Switch):
    def __init__(self, props, expected=False):
        Switch.__init__(self, props, expected)


    def reboot(self):
        ssh = self._get_ssh()
        if ssh.create_session():
            if ssh.execute_command('set status switch reboot',prompt="[all/noentries/nopipeline/none]"):
                if ssh.execute_command('noentries',prompt="(y/n)"):
                    ssh.execute_command('y', prompt=None, eof=True)
                    return True


    def break_gateway(self, seconds=0):
        raise Exception('break method is not implemented by this switch {}'.format(self.name))

    def delete_groups(self):
        ssh = self._get_ssh()
        if ssh.create_session():
            if ssh.execute_command('del config group groupid all'):
                ssh.close()
                return True

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


    def _get_ssh(self):
        return NoviflowSSH(ip=self.ip, user=self.user, port=self.port, password=self.password)
