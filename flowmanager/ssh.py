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
from pexpect import pxssh


class SSH(object):

    """docstring for ClassName"""

    def __init__(self, ip, user, port=22, password=None, prompt=None, timeout=30):
        self.ip = ip
        self.user = user
        self.port = port
        self.password = password
        self.prompt = prompt
        self.timeout = timeout
        self.session_open = False

    def is_session_open(self):
        return self.session_open

    # def execute_single_command(self, command):
    #     target = "{}@{}".format(self.user, self.ip) if self.user else self.ip
    #     port = self.port if self.port else 22

    #     cmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p {} {} '{}'".format(
    #         port, target, command)
    #     if self.password:
    #         child = pexpect.spawn(cmd)
    #         i = child.expect([pexpect.TIMEOUT, unicode(
    #             '(?i)password'), unicode('No route to host'), pexpect.EOF])
    #         if i == 0:
    #             logging.error('Could not connect to host via SSH')
    #             return False
    #         if i == 2:
    #             logging.error('No route to host')
    #             return False
    #         if i == 3:
    #             logging.error('Reached end of file')
    #             return False

    #         child.sendline(self.password)
    #         child.expect([pexpect.TIMEOUT, pexpect.EOF])
    #         child.close()
    #         return child.before()

    #     else:
    #         output = subprocess.check_output(cmd, shell=True)

    #     return True

    def execute_single_command(self, command):
        try:
            s = pxssh.pxssh()
            s.login(self.ip, self.user, self.password)
            s.sendline(command)
            s.prompt()
            logging.info(s.before)
            s.logout()
        except pxssh.ExceptionPxssh, msg:
            logging.error(str(msg))

    def create_session(self):
        ssh_command = 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p {} {}@{}'.format(
            self.port, self.user, self.ip)
        logging.debug('SSH: connecting to %s', ssh_command)
        self.child = pexpect.spawn(ssh_command)
        result = self.child.expect(
            [pexpect.TIMEOUT, unicode('(?i)password')], timeout=self.timeout)
        if result == 0:
            logging.error(
                'ERROR: could not connect to noviflow via SSH. %s@%s port ({%s)', self.user, self.ip, self.port)
            return False
        else:
            self.child.sendline(self.password)
            if self.child.expect([pexpect.TIMEOUT, unicode(self.prompt)], timeout=self.timeout) == 0:
                return False
            else:
                logging.debug('SSH session created with success')
                self.session_open = True
                return True

    def execute_command(self, command, prompt=None, timeout=None, eof=False):
        if (not self.session_open):
            self.create_session()

        prompt = prompt if prompt else self.prompt
        timeout = timeout if timeout else self.timeout

        logging.debug('SSH: (%s) executing command %s , prompt %s, timeout %s',
                      self.ip, command, prompt, timeout)
        self.child.sendline(command)
        expect_options = [pexpect.TIMEOUT, unicode(prompt)] if not eof else [
            pexpect.TIMEOUT, unicode(prompt), pexpect.EOF]
        if self.child.expect(expect_options, timeout=timeout) != 0:
            logging.debug(
                'SSH: (%s) command executed. Ouput is: \n %s', self.ip, self.child.before)
            return self.child.before

    def close(self):
        logging.debug('SSH: (%s) closing connection.', self.ip)
        self.session_open = False
        self.child.sendline('exit')
        self.child.expect([pexpect.TIMEOUT, pexpect.EOF])
        self.child.close()


class NoviflowSSH(SSH):
    def __init__(self, ip, user, port, password=None, prompt=None, timeout=3):
        SSH.__init__(self, ip, user, port, password,
                     prompt if prompt else "#", timeout)

    def create_session(self):
        result = super(NoviflowSSH, self).create_session()
        if result:
            result = self.execute_command('show config switch hostname')
            if result:
                regex = re.compile(r'Hostname:\s*(\S+)', re.IGNORECASE)
                match = regex.findall(self.child.before)
                self.prompt = '{}#'.format(match[0]) if match else self.prompt
                logging.debug('NOVIFLOW: current prompt %s', self.prompt)

                result = self.execute_command('show config page')
                if result:
                    pageRegex = re.compile(r'(off)', re.IGNORECASE)
                    pageConfig = pageRegex.findall(self.child.before)
                    if not pageConfig:
                        logging.debug("NOVIFLOW: disabling config page ")
                        return self.execute_command('set config page off')
                    else:
                        return result


'''
    def execute_single_command(self, command):
        cmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p {} {}@{} '{}'".format(
            self.port, self.user, self.ip, command)
        print(cmd)
        if self.password:
            child = pexpect.spawn(cmd)
            i = child.expect(
                [pexpect.EOF, pexpect.TIMEOUT, unicode('(?i)password')])
            if i == 0:
                print('ERROR: reached end of file. {}:{}'.format(
                    self.ip, self.port))
                return False
            if i == 1:
                print('ERROR: could not connect to controller via SSH. {}:{}'.format(
                    self.ip, self.port))
                return False

            child.sendline(self.password)
            child.expect([pexpect.TIMEOUT, pexpect.EOF])
            child.close()
        return child.before
'''
