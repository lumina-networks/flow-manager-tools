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
        self.controllers = []

        self.ip = ip
        self.user = user
        self.port = port
        self.password = password
        self.prompt = prompt
        self.timeout = timeout
        logging.getLogger().setLevel(logging.DEBUG)
        
    def create_session(self):
        ssh_command = 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p {} {}@{}'.format(self.port, self.user, self.ip)
        logging.debug(ssh_command)
        self.child = pexpect.spawn(ssh_command)
        result = self.child.expect([pexpect.TIMEOUT, unicode('(?i)password')], timeout=self.timeout)
        # logging.debug(self.child.before)
        if result == 0:
            logging.debug('ERROR: could not connect to noviflow via SSH. %s@%s port ({%s)', self.user, self.ip, self.port)
            self.close()
            return False
        else:
            self.child.sendline(self.password)
            logging.debug('Output: %s', self.child.before)
            #pdb.set_trace()
            if self.child.expect([pexpect.TIMEOUT, unicode(self.prompt)], timeout=self.timeout) == 0:
                logging.debug(self.child.before)
                logging.debug(self.prompt)
                logging.debug("Error")
                self.close()
                return False
            else:
                return True

    def execute_command(self, command, prompt = None):
        self.child.sendline(command)
        prompt = prompt if prompt else self.prompt
        if self.child.expect([pexpect.TIMEOUT, unicode(prompt)], timeout=self.timeout) == 0:
            self.close()
    
    def close(self):
        self.child.sendline('exit')
        self.child.expect([pexpect.TIMEOUT,pexpect.EOF])
        self.child.close()

class NoviflowSSH(SSH):
    def __init__(self, ip, user, port, password=None, prompt = None, timeout=3):
        SSH.__init__(self, ip, user, port, password, prompt if prompt else '#', timeout)
        self.create_session()

    def create_session(self):
        result = SSH(self.ip, self.user, self.port, self.password).create_session()
        if result:
            self.execute_command('ifconfig')

            regex = re.compile(r'Hostname:\s*(\S+)', re.IGNORECASE)
            match = regex.findall(child.before)
            PROMPT = '{}#'.format(match[0]) if match else None

if __name__ == "__main__":
    NoviflowSSH('192.168.50.40', 'vagrant', 22, 'vagrant', '#')