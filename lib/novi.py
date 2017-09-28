"""
Description: Library to interact with Noviflow devices
Author: Bhavish Khatri
Company: Telstra

Copyright Telstra 2017
All Rights Reserved
"""
import pexpect

class NoviFlow:
    """NoviFlow class to interact with switch"""

    def __init__(self):
        """Initializer"""
        self.username = 'superuser'
        self.password = 'Telstra123'
        self.timeout = 30
        self.client = None
    
    def connect(self, switch):
        """Connect to switch"""
        command = 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no {}@{}'.format(
            self.username, switch)
        self.client = pexpect.spawn(command)
        i = self.client.expect([pexpect.TIMEOUT, unicode('(?i)password')], timeout=self.timeout)
        if i == 0:
            print('ERROR: could not connect to noviflow via SSH.')
            self.client = None
            return

        self.client.sendline(self.password)
        i = self.client.expect([pexpect.TIMEOUT, unicode('#')], timeout=self.timeout)
        if i == 0:
            print('ERROR: cannot get prompt after entering password')
            self.client = None
            return
        
    def run(self, command):
        """Run a command on the switch and receive the output"""
        if self.client is None:
            print 'Not connected'

        self.client.sendline(command)
        i = self.client.expect([pexpect.TIMEOUT, unicode('[\w\d]{4}-or-[\d]{3}#')], timeout=self.timeout)
        if i == 0:
            print('ERROR: Device failed to respond in time')
            return

        lines = self.client.before.splitlines()
        lines = lines[1:-1]

        return '\n'.join(lines)

    def disconnect(self):
        self.client.sendline('exit')
        self.client.expect([pexpect.TIMEOUT,pexpect.EOF], timeout=self.timeout)
        self.client.close()
        self.client = None

