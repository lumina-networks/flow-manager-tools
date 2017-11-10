"""SSH

This module contains the primitives to manipulate SSH sessions.

"""
import threading
import re
import os
import requests
from requests.auth import HTTPBasicAuth
import subprocess
import json
import pexpect
import random
import time
import pdb
import logging
from functools import partial

class SSH(object):

    """docstring for ClassName"""
    def __init__(self, ip, user, port, password=None, prompt = None, timeout=3):
        self.ip = ip
        self.user = user
        self.port = port
        self.password = password
        self.prompt = prompt
        self.timeout = timeout
        self.ssh_command = 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p {} {}@{}'.format(self.port, self.user, self.ip)

    def create_session(self):
        self.child = pexpect.spawn(self.ssh_command)
        result = self.child.expect([pexpect.TIMEOUT, unicode('(?i)password')], timeout=self.timeout)
        if result == 0:
            logging.error('ERROR: could not connect to noviflow via SSH. %s@%s port ({%s)', self.user, self.ip, self.port)
            return False
        else:
            self.child.sendline(self.password)
            if self.child.expect([pexpect.TIMEOUT, unicode(self.prompt)], timeout=self.timeout) == 0:
                return False
            else:
                logging.debug('SSH session created with success')
                return True

    def execute_command(self, command, prompt=None, timeout=None):
        prompt = prompt if prompt else self.prompt
        timeout = timeout if timeout else self.timeout

        logging.debug('SSH: (%s) executing command %s , prompt %s, timeout %s',self.ip, command, prompt, timeout)
        self.child.sendline(command)
        if self.child.expect([pexpect.TIMEOUT, unicode(prompt)], timeout=timeout) != 0:
            logging.debug('SSH: (%s) command executed. Ouput is: \n %s', self.ip, self.child.before)
            return self.child.before

    def close(self):
        logging.debug('SSH: (%s) closing connection.', self.ip)
        self.child.sendline('exit')
        self.child.expect([pexpect.TIMEOUT,pexpect.EOF])
        self.child.close()

class NoviflowSSH(SSH):
    def __init__(self, ip, user, port, password=None, prompt=None, timeout=3):
        SSH.__init__(self, ip, user, port, password, prompt if prompt else "#", timeout)

    def create_session(self):
        result = super(NoviflowSSH, self).create_session()
        if result:
            result = self.execute_command('show config switch hostname')
            if result:
                regex = re.compile(r'Hostname:\s*(\S+)', re.IGNORECASE)
                match = regex.findall(self.child.before)
                self.prompt = '{}#'.format(match[0]) if match else self.prompt
                logging.debug('NOVIFLOW: current prompt %s',self.prompt)

                result = self.execute_command('show config page')
                if result:
                    pageRegex = re.compile(r'(off)', re.IGNORECASE)
                    pageConfig = pageRegex.findall(self.child.before)
                    if not pageConfig:
                        logging.debug("NOVIFLOW: disabling config page ")
                        return self.execute_command('set config page off')
                    else:
                        return result
