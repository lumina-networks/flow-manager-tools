import re
import subprocess
from flowmanager.switch import Switch
from flowmanager.ssh import SSH


class OVS(Switch):
    def __init__(self, props, expected=False):
        Switch.__init__(self, props, expected)

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

    def delete_flows(self):
        if self.execute_local:
            output = subprocess.check_output(
                "sudo ovs-ofctl del-flows {} --protocol=Openflow13".format(self.name), shell=True)
        else:
            pass # To be completed for remote OVS

    def delete_groups(self):
        if self.execute_local:
            output = subprocess.check_output(
                "sudo ovs-ofctl del-groups {} --protocol=Openflow13".format(self.name), shell=True)
        else:
            pass
