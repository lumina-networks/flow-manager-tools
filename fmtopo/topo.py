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
from functools import partial

calculated_flow_exception = ['table/0/flow/fm-sr-link-discovery']

_DEFAULT_HEADERS = {
    'content-type': 'application/json',
    'accept': 'application/json'
}

def _get_flow_version(cookie):
    return (int(cookie) & 0x00000000FF000000) >> 24

def _get_flow_bscid(cookie):
    return (int(cookie) & 0x00FFFFFF00000000) >> 32

def _check_mandatory_values(obj, names):
    for name in names:
        if name not in obj or not obj[name]:
            raise Exception("{} is missing in object {}".format(name, obj))

def _reboot_switch_ovs(name):
    output = subprocess.check_output(
        "sudo ovs-vsctl get-controller {}".format(name), shell=True)
    controllersRegex = re.compile(r'(tcp:\d+\.\d+\.\d+\.\d+\:\d+)', re.IGNORECASE)
    match = controllersRegex.findall(output)
    if not match:
        print "ERROR: cannot get controllers for {}".format(name)
        return False
    controllers = ' '.join(match)
    output =  subprocess.check_output("sudo ovs-vsctl del-controller {}".format(name), shell=True)
    _delete_flows_ovs(name)
    _delete_groups_ovs(name)
    time.sleep(5)
    output =  subprocess.check_output("sudo ovs-vsctl set-controller {} {}".format(name,controllers), shell=True)

def _execute_commands_locally(cmds):
    for cmd in cmds:
        output = subprocess.check_output(cmd, shell=True)
    return True

def _delete_flows_ovs(name):
    output =  subprocess.check_output(
        "sudo ovs-ofctl del-flows {} --protocol=Openflow13".format(name), shell=True)

def _delete_groups_ovs(name):
    output =  subprocess.check_output(
        "sudo ovs-ofctl del-groups {} --protocol=Openflow13".format(name), shell=True)


def _get_flows_groups_from_ovs(node, name,prefix=None):
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
                    print "ERROR: duplicated bsc id {} in node {}".format(bscid,name)
                node['bscids'][int(bscid)] = number

def _get_controller_roles_switch_ovs(node, name):
    return None

def _get_noviflow_connection_prompt(ip, port, user, password):
    child = pexpect.spawn('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p {} {}@{}'.format(port, user, ip))
    i = child.expect([pexpect.TIMEOUT, unicode('(?i)password')])
    if i == 0:
        print('ERROR: could not connect to noviflow via SSH. {}@{} port ({})'.format(user, ip, port))
        return None, None

    child.sendline(password)
    i = child.expect([pexpect.TIMEOUT, unicode('#')])
    if i == 0:
        print('ERROR: cannot get prompt after entering password for {}@{} port ({})'.format(user, ip, port))
        child.sendline('exit')
        child.expect(pexpect.EOF)
        child.close()
        return None, None

    child.sendline('show config switch hostname')
    i = child.expect([pexpect.TIMEOUT, unicode('#')])
    if i == 0 or not child.before:
        print('ERROR: cannot prompt after sending get hostname command for {}@{} port ({})'.format(user, ip, port))
        child.sendline('exit')
        child.expect(pexpect.EOF)
        child.close()
        return None, None

    hostnameIdRegex = re.compile(r'Hostname:\s*(\S+)', re.IGNORECASE)
    match = hostnameIdRegex.findall(child.before)
    PROMPT = '{}#'.format(match[0]) if match else None

    child.sendline('show config page')
    i = child.expect([pexpect.TIMEOUT, PROMPT])
    if i == 0 or not child.before:
        print('ERROR: cannot prompt after getting page configuration command for {}@{} port ({})'.format(user, ip, port))
        child.sendline('exit')
        child.expect(pexpect.EOF)
        child.close()
        return None, None

    pageRegex = re.compile(r'(off)', re.IGNORECASE)
    pageConfig = pageRegex.findall(child.before)
    if not pageConfig:
        print('WARNING: page is not disabled and commands with long output might not work. Executing "set config page off" for {}@{} port ({})'.format(user, ip, port))
        child.sendline('set config page off')
        i = child.expect([pexpect.TIMEOUT, PROMPT])
        if i == 0 or not child.before:
            print('ERROR: cannot prompt after getting page configuration command for {}@{} port ({})'.format(user, ip, port))
            child.sendline('exit')
            child.expect(pexpect.EOF)
            child.close()
            return None, None

    return child, PROMPT

def _close_noviflow_connection(child):
    child.sendline('exit')
    child.expect(pexpect.EOF)
    child.close()

def _reboot_switch_noviflow(ip, port, user, password):
    child, PROMPT = _get_noviflow_connection_prompt(ip, port, user, password)
    if  not child or not PROMPT:
        print('ERROR: could not connect to noviflow via SSH. {}@{} port ({})'.format(user, ip, port))
        return False
    child.sendline('set status switch reboot')
    i = child.expect([pexpect.TIMEOUT, 'none'])
    if i == 0 or not child.before:
        print('ERROR: cannot reboot switch for {}@{} port ({})'.format(user, ip, port))
        _close_noviflow_connection(child)
        return False
    child.sendline('none')
    child.expect(pexpect.EOF)
    child.close()
    return True

def _execute_commands_in_switch_noviflow(ip, port, user, password, cmds):
    child, PROMPT = _get_noviflow_connection_prompt(ip, port, user, password)
    if  not child or not PROMPT:
        print('ERROR: could not connect to noviflow via SSH. {}@{} port ({})'.format(user, ip, port))
        return False
    for cmd in cmds:
        print "sending cmd {} to switch {}:{}".format(cmd,ip,port)
        child.sendline(cmd)
        i = child.expect([pexpect.TIMEOUT, PROMPT])
        if i == 0 or not child.before:
            print('ERROR: cannot send command {}{ to switch for {}@{} port ({})'.format(cmd, user, ip, port))
            _close_noviflow_connection(child)
            return False
    _close_noviflow_connection(child)
    return True

def _delete_flows_noviflow(ip, port, user, password):
    child, PROMPT = _get_noviflow_connection_prompt(ip, port, user, password)
    if  not child or not PROMPT:
        print('ERROR: could not connect to noviflow via SSH. {}@{} port ({})'.format(user, ip, port))
        return False

    child.sendline('del config flow tableid all')
    i = child.expect([pexpect.TIMEOUT, PROMPT])
    if i == 0 or not child.before:
        print('ERROR: cannot delete flows for {}@{} port ({})'.format(user, ip, port))
        _close_noviflow_connection(child)
        return False
    _close_noviflow_connection(child)
    return True

def _delete_groups_noviflow(ip, port, user, password):
    child, PROMPT = _get_noviflow_connection_prompt(ip, port, user, password)
    if  not child or not PROMPT:
        print('ERROR: could not connect to noviflow via SSH. {}@{} port ({})'.format(user, ip, port))
        return False

    child.sendline('del config group groupid all')
    i = child.expect([pexpect.TIMEOUT, PROMPT])
    if i == 0 or not child.before:
        print('ERROR: cannot delete groups for {}@{} port ({})'.format(user, ip, port))
        _close_noviflow_connection(child)
        return False
    _close_noviflow_connection(child)
    return True

def _get_flows_groups_from_noviflow(node, ip, port, user, password, prefix=None):
    child, PROMPT = _get_noviflow_connection_prompt(ip, port, user, password)
    if not child or not PROMPT:
        print('ERROR: could not connect to noviflow via SSH. {}@{} port ({})'.format(user, ip, port))
        return False

    child.sendline('show stats group groupid all')
    i = child.expect([pexpect.TIMEOUT, PROMPT])
    if i == 0 or not child.before:
        print('ERROR: cannot get groups for {}@{} port ({})'.format(user, ip, port))
        _close_noviflow_connection(child)
        return False

    groupIdRegex = re.compile(r'Group id:\s*(\d+)', re.IGNORECASE)
    packetCountRegex = re.compile(r'Reference count:\s*\d+\s*\S\s+Packet count:\s*(\d+)', re.IGNORECASE)
    byteCountRegex = re.compile(r'Byte count:\s*(\d+)', re.IGNORECASE)

    current_group = None
    for line in child.before.splitlines():
        match = groupIdRegex.findall(line)
        if match:
            current_group = {}
            node['groups'][int(match[0])] = current_group
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

    child.sendline('show status flow tableid all')
    i = child.expect([pexpect.TIMEOUT, PROMPT])
    if i == 0 or not child.before:
        print('ERROR: cannot get flows for {}@{} port ({})'.format(user, ip, port))
        _close_noviflow_connection(child)
        return False

    cookies = re.compile(r'Cookie\s*=\s*(\S+)', re.IGNORECASE).findall(child.before)
    packetCounts = re.compile(r'Packet_count\s*=\s*(\d+)', re.IGNORECASE).findall(child.before)
    byteCounts = re.compile(r'Byte_count\s*=\s*(\d+)', re.IGNORECASE).findall(child.before)

    cookiesLen = len(cookies) if cookies else 0

    if cookiesLen >0:
        if not packetCounts or cookiesLen != len(packetCounts):
            print('ERROR: flows packets length is different for {}@{} port ({})'.format(user, ip, port))
            _close_noviflow_connection(child)
            return False

        if not byteCounts or cookiesLen != len(byteCounts):
            print('ERROR: flows bytes length is different for {}@{} port ({})'.format(user, ip, port))
            _close_noviflow_connection(child)
            return False

    while cookiesLen > 0:
        cookiesLen -= 1
        number = int('0x{}'.format(cookies[cookiesLen]), 16)
        if prefix is None or number >> 56 == prefix:
            node['flows'][str(number)] = {
                'packets': packetCounts[cookiesLen],
                'bytes': byteCounts[cookiesLen]
            }
            node['cookies'][str(number)] = node['flows'][str(number)]
            bscid = _get_flow_bscid(number)
            if bscid in node['bscids']:
                print "ERROR: duplicated bsc id {} in node with ip {} and port {}".format(bscid,ip,port)
            node['bscids'][int(bscid)] = number

    _close_noviflow_connection(child)
    return True

def _get_controller_roles_switch_noviflow(ip, port, user, password):
    child, PROMPT = _get_noviflow_connection_prompt(ip, port, user, password)
    if  not child or not PROMPT:
        print('ERROR: could not connect to noviflow via SSH. {}@{} port ({})'.format(user, ip, port))
        return False
    child.sendline('show status ofchannel')
    i = child.expect([pexpect.TIMEOUT, PROMPT])
    if i == 0 or not child.before:
        print('ERROR: cannot get groups for {}@{} port ({})'.format(user, ip, port))
        _close_noviflow_connection(child)
        return False

    rolesRegex = re.compile(r'Role\s+-\s+(\S+)', re.IGNORECASE)
    roles = rolesRegex.findall(child.before)

    child.sendline('exit')
    child.expect(pexpect.EOF)
    child.close()
    return roles


def contains_filters(filters=None,value=None):
    if not value:
        return False
    if not filters or len(filters) <= 0:
        return True
    for fil in filters:
        if fil not in value:
            return False
    return True


class Topo(object):

    def __init__(self, props):
        # Disable warnings
        try:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except:
            pass

        self.props = props
        self.controllers = []
        self.controllers_name = {}
        self.hosts = {}
        self.hosts_ip = {}
        self.switches = {}
        self.switches_openflow_names = {}
        self.links = []
        self.interfaces = {}
        self.portmap = {}
        self.portdestinationswitch = {}
        self.portdestinationport = {}
        self.host_connected_switch = {}
        self.number_of_swiches_links = 0
        self.number_of_switches = 0

        if props.get('host'):
            for host in props['host']:
                _check_mandatory_values(host, ['name', 'ip'])
                self.hosts[host['name']] = host
                self.hosts_ip[host['name']] = host['ip'].split('/')[0]
                host['type'] = 'mininet' if not host.get('type') else host['type']
                host['user'] = 'vagrant' if not host.get('user') else host['user']
                host['password'] = 'vagrant' if not host.get('password') else host['password']
                host['port'] = 22 if not host.get('port') else host['port']

        self.number_of_switches = 0
        if props.get('switch'):
            self.number_of_switches = len(props['switch'])
            for switch in props['switch']:
                _check_mandatory_values(switch, ['name', 'dpid'])
                self.switches[switch['name']] = switch
                self.switches_openflow_names[switch['name']] = "openflow:" + str(int(switch['dpid'], 16))
                switch['type'] = 'mininet' if not switch.get('type') else switch['type']
                switch['user'] = 'vagrant' if not switch.get('user') else switch['user']
                switch['password'] = 'vagrant' if not switch.get('password') else switch['password']
                switch['ip'] = '127.0.0.1' if not switch.get('ip') else switch['ip']
                switch['port'] = 22 if not switch.get('port') else switch['port']
                switch['oname'] = "openflow:" + str(int(switch['dpid'], 16))


        if props.get('link'):
            ports = {}
            for link in props['link']:
                _check_mandatory_values(link, ['source', 'destination'])
                src_name = link['source']
                dst_name = link['destination']
                self.links.append(link)

                source = None
                if src_name in self.switches:
                    src_port = link.get('source_port')
                    if not src_port:
                        if src_name not in ports:
                            ports[src_name] = 1
                        link['source_port'] = ports[src_name]
                        src_port = ports[src_name]
                        ports[src_name] = ports[src_name] + 1

                destination = None
                if dst_name in self.switches:
                    dst_port = link.get('destination_port')
                    if not dst_port:
                        if dst_name not in ports:
                            ports[dst_name] = 1
                        link['destination_port'] = ports[dst_name]
                        dst_port = ports[dst_name]
                        ports[dst_name] = ports[dst_name] + 1

                if src_name in self.switches and dst_name in self.switches:
                    self.number_of_swiches_links = self.number_of_swiches_links + 2

                    src_name_port = self.switches_openflow_names[src_name] + ':' + str(src_port)
                    dst_name_port = self.switches_openflow_names[dst_name] + ':' + str(dst_port)
                    self.portdestinationswitch[src_name_port] = self.switches_openflow_names[dst_name]
                    self.portdestinationswitch[dst_name_port] = self.switches_openflow_names[src_name]
                    self.portdestinationport[src_name_port] = dst_name_port
                    self.portdestinationport[dst_name_port] = src_name_port

                if (src_name in self.hosts and dst_name in self.switches):
                    self.host_connected_switch[src_name] = dst_name
                elif (dst_name in self.hosts and src_name in self.switches):
                    self.host_connected_switch[dst_name] = src_name

        if props.get('interfaces'):
            for interface in props['interfaces']:
                _check_mandatory_values(link, ['name', 'switch'])
                self.interfaces.append(interface)

        if props.get('controller'):
            for ctrl in props['controller']:
                _check_mandatory_values(ctrl, ['name', 'ip'])
                self.controllers.append(ctrl)
                self.controllers_name[ctrl['name']] = ctrl
        else:
            self.controllers.append({'name': 'c0', 'ip': '127.0.0.1'})
            self.controllers_name[self.controllers[0]['name']] = self.controllers[0]

        ctrl = self.controllers[0]
        self.ctrl_protocol = 'http' if not ctrl.get('protocol') else ctrl['protocol']
        self.ctrl_ip = '127.0.0.1' if not ctrl.get('ip') else ctrl['ip']
        self.ctrl_port = '8181' if not ctrl.get('port') else int(ctrl['port'])
        self.ctrl_user = 'admin' if not ctrl.get('user') else ctrl['user']
        self.ctrl_password = 'admin' if not ctrl.get('password') else ctrl['password']
        self.ctrl_timeout = 60 if not ctrl.get('timeout') else int(ctrl['timeout'])
        if props.get('controller_vip'):
            self.ctrl_ip = props.get('controller_vip')

    def containsSwitch(self, name):
        return str(name) in self.switches_openflow_names or str(name) in self.switches_openflow_names.values()

    def get_random_switch(self):
        return random.choice(self.switches.keys())

    def get_random_controller(self):
        return random.choice(self.controllers_name.keys())

    def reboot_controller(self, name):
        ctrl = self.controllers_name.get(name)
        if not ctrl:
            print "ERROR: {} controller does not exists".format(name)
            return False

        print "INFO: rebooting {} controller with ip {}".format(name, ctrl['ip'])
        sshuser = ctrl.get('sshuser')
        sshpassword = ctrl.get('sshpassword')
        sshport = ctrl.get('sshport')

        target = "{}@{}".format(sshuser,ctrl['ip']) if sshuser else ctrl['ip']
        port = sshport if sshport else 22

        cmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p {} {} 'sudo service brcd-bsc stop; sleep 5; sudo service brcd-bsc start'".format(port, target)
        if sshpassword:
            child = pexpect.spawn(cmd)
            i = child.expect([pexpect.TIMEOUT, unicode('(?i)password')])
            if i == 0:
                print('ERROR: could not connect to controller via SSH. {} port ({})'.format(target, port))
                return False

            child.sendline(sshpassword)
            child.expect(pexpect.EOF)
            child.close()

        else:
            output = subprocess.check_output(cmd, shell=True)

        return True

    def reboot_switch(self, name):
        switch = self.switches.get(name)
        if not switch:
            print "ERROR: {} switch does not exists".format(name)
            return False

        print "INFO: rebooting {} switch".format(name)
        if switch['type'] == 'noviflow':
            return _reboot_switch_noviflow(switch['ip'], switch['port'],switch['user'],switch['password'])
        else:
            return _reboot_switch_ovs(name)

    def break_gw_switch(self, name, seconds=30):
        switch = self.switches.get(name)
        if not switch:
            print "ERROR: {} switch does not exists".format(name)
            return False
        seconds = int(seconds)
        seconds = 0 if not seconds or seconds <=0 else seconds
        print "INFO: trying to break connectivity to the switch {} switch".format(name)
        if not switch['disable_gw'] or len(switch['disable_gw']) <=0 or not switch['enable_gw'] or len(switch['enable_gw']) <=0:
            print "ERROR: enable or disable gw commands not found in switch {} switch".format(name)
            return False
        if switch['type'] == 'noviflow':
            if not _execute_commands_in_switch_noviflow(switch['ip'], switch['port'],switch['user'],switch['password'],switch['disable_gw']):
                return False
            time.sleep(seconds)
            return _execute_commands_in_switch_noviflow(switch['ip'], switch['port'],switch['user'],switch['password'],switch['enable_gw'])
        else:
            if not _execute_commands_locally(switch['disable_gw']):
                return False
            time.sleep(seconds)
            return _execute_commands_locally(switch['enable_gw'])

    def delete_groups(self, name):
        switch = self.switches.get(name)
        if not switch:
            print "ERROR: {} switch does not exists".format(name)
            return False

        print "INFO: deleting groups on {} switch".format(name)
        if switch['type'] == 'noviflow':
            return _delete_groups_noviflow(switch['ip'], switch['port'],switch['user'],switch['password'])
        else:
            return _delete_groups_ovs(name)

    def delete_flows(self, name):
        switch = self.switches.get(name)
        if not switch:
            print "ERROR: {} switch does not exists".format(name)
            return False

        print "INFO: deleting flows on {} switch".format(name)
        if switch['type'] == 'noviflow':
            return _delete_flows_noviflow(switch['ip'], switch['port'],switch['user'],switch['password'])
        else:
            return _delete_flows_ovs(name)

    def get_flows_groups_from_switches(self, prefix=None):
        nodes = {}
        threads = []
        for name, switch in self.switches.iteritems():
            oname = switch['oname']
            node = {'flows': {}, 'cookies': {}, 'groups': {}, 'bscids': {}}
            nodes[oname] = node
            if switch['type'] == 'noviflow':
                t = threading.Thread(target=_get_flows_groups_from_noviflow, args=(node,switch['ip'],switch['port'],switch['user'],switch['password'],prefix,))
            else:
                t = threading.Thread(target=_get_flows_groups_from_ovs, args=(node,name,prefix,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
        return nodes

    def get_controller_role(self, name):
        switch = self.switches.get(name)
        if not switch:
            print "ERROR: {} switch does not exists".format(name)
            return False

        if switch['type'] == 'noviflow':
            return _get_controller_roles_switch_noviflow(switch['ip'], switch['port'],switch['user'],switch['password'])
        else:
            return _get_controller_roles_switch_ovs(name)

    def check_roles(self, topology_name='flow:1'):
        found_error = False
        for name in self.switches_openflow_names:
            oname = self.switches_openflow_names[name]
            roles = self.get_controller_role(name)
            owner = self._get_node_cluster_owner(oname)
            if owner and roles and 'Master' not in roles:
                print "ERROR: {} node does not contain master in the switch. Current roles {}".format(oname,roles)
                found_error = True
        if not found_error:
            print "OK: {} nodes roles has been detected properly.".format(len(self.switches_openflow_names))
            return True
        return False

    def check_nodes(self, running=True, topology_name='flow:1'):
        nodes, links = self._get_nodes_and_links(topology_name)
        found_error = False
        for name in self.switches_openflow_names:
            oname = self.switches_openflow_names[name]
            if running and oname not in nodes:
                print "ERROR: topology({}) {} node not found".format(topology_name, oname)
                found_error = True
            elif not running and oname in nodes:
                print "ERROR: topology({}) {}  node is still up when network is not running".format(topology_name, oname)
                found_error = True

        if not found_error:
            print "OK: topology({})  {} nodes has been detected properly.".format(topology_name, len(self.switches_openflow_names))
            return True
        return False

    def check_links(self, running=True, topology_name='flow:1'):
        nodes, links = self._get_nodes_and_links(topology_name)
        found_error = False
        all_ports=[]
        for openflowport in self.portdestinationswitch:
            dstSwitch = self.portdestinationswitch[openflowport]
            dstPort = self.portdestinationport[openflowport]

            all_ports.append(openflowport)
            if running and openflowport not in links:
                print "ERROR: topology({}) {} port link not found to {}".format(topology_name, openflowport,dstPort)
                found_error = True
            elif running and links[openflowport].get('destination').get('dest-node') != dstSwitch:
                print "ERROR: topology({}) unexpected destination switch for {} port and link {}. Expected {}".format(topology_name, openflowport,links[openflowport], dstSwitch)
                found_error = True
            elif running and links[openflowport].get('destination').get('dest-tp') != dstPort:
                print "ERROR: topology({}) unexpected destination port for {} port and link {}. Expected {}".format(topology_name, openflowport,links[openflowport], dstPort)
                found_error = True
            elif not running and openflowport in links:
                print "ERROR: topology({}) {} port is still up when network is not running".format(topology_name, openflowport)
                found_error = True

        if len(all_ports) != len(links):
            print "WARNING: topology({}) {} links expected and {} has been detected by the controller.".format(topology_name, len(all_ports),len(links))

        for link in links:
            if link not in all_ports:
                print "WARNING: topology({}) {} link exists but not defined in the topology.".format(topology_name, link)


        if not found_error:
            print "OK: topology({}) {} links has been detected properly.".format(topology_name, len(self.portdestinationswitch))
            return True

        return False

    def check_flows(self, prefix=0x1f, check_stats=False):
        error_found = False
        switch_flows_groups = self.get_flows_groups_from_switches(prefix)
        calculated_nodes = self._get_calculated_flows_groups()
        config_nodes = self._get_flow_group(self._get_config_openflow(), prefix)
        operational_nodes = self._get_flow_group(self._get_operational_openflow(), prefix)

        for nodeid, node in config_nodes.iteritems():

            for flowid, flow in node['flows'].iteritems():
                if 'match' not in flow:
                    print "WARNING: flow {} does not have match".format(flowid)
                    continue
                for flowid2, flow2 in node['flows'].iteritems():
                    if 'match' not in flow2:
                        continue
                    if flowid == flowid2:
                        continue
                    if flow.get('table') != flow2.get('table'):
                        continue
                    if compare_dictionaries(flow['match'],flow2['match']) and flow.get('priority') == flow2.get('priority'):
                        print "ERROR: DUPLICATED MATCH CRITERIA flow id {} and {} contains the same match. Check elines/etree service with the same match criteria. {} {}".format(flowid, flowid2,flow['match'],flow2['match'])
                        error_found = True

            for bscid, cookie in node['bscids'].iteritems():
                flowid = node['cookies'][cookie]
                version = _get_flow_version(cookie)
                if nodeid not in operational_nodes or bscid not in operational_nodes[nodeid]['bscids']:
                    print "ERROR: (config) node {} flow {} bscid {} cookie {} not running, not found in operational data store".format(nodeid, flowid, bscid, cookie)
                    error_found = True
                elif version != _get_flow_version(operational_nodes[nodeid]['bscids'][bscid]):
                    print "WARNING: (config) node {} flow {} bscid {} cookie {} operational version is different. Config version {}, operational version {}".format(nodeid, flowid, bscid,cookie, version,_get_flow_version(operational_nodes[nodeid]['bscids'][bscid]))
                    error_found = True

                if nodeid not in switch_flows_groups or bscid not in switch_flows_groups[nodeid]['bscids']:
                    print "ERROR: (config) node {} flow {} bscid {} cookie {} not running, not found in the switch".format(nodeid, flowid, bscid,cookie)
                    error_found = True
                elif version != _get_flow_version(switch_flows_groups[nodeid]['bscids'][bscid]):
                    print "WARNING: (config) node {} flow {} bscid {} cookie {} switch version is different. Config version {}, switch version {}".format(nodeid, flowid, bscid,cookie,version,_get_flow_version(switch_flows_groups[nodeid]['bscids'][bscid]))
                    error_found = True

                if flowid not in calculated_flow_exception and (nodeid not in calculated_nodes or flowid not in calculated_nodes[nodeid]['flows']):
                    print "ERROR: (config) node {} flow {} bscid {} cookie {} not present in calculated nodes".format(nodeid, flowid, bscid,cookie)
                    error_found = True

            for groupid in node['groups']:
                if nodeid not in operational_nodes or 'groups' not in operational_nodes[nodeid] or groupid not in operational_nodes[nodeid]['groups']:
                    print "ERROR: (config) node {} group {} not running".format(nodeid, groupid)
                    error_found = True
                if nodeid not in calculated_nodes or groupid not in calculated_nodes[nodeid]['groups']:
                    print "ERROR: (config) node {} group {} group not present in calculated groups".format(nodeid, groupid)
                    error_found = True
                if nodeid not in switch_flows_groups or groupid not in switch_flows_groups[nodeid]['groups']:
                    print "ERROR: (config) node {} group {} configured but not in the switch".format(nodeid, groupid)
                    error_found = True

        for nodeid in operational_nodes:
            node = operational_nodes[nodeid]
            for bscid, cookie in node['bscids'].iteritems():
                version = _get_flow_version(cookie)
                flowid = node['cookies'][cookie]

                if nodeid not in config_nodes or bscid not in config_nodes[nodeid]['bscids']:
                    print "ERROR: (operational) node {} flowid {} bscid {} cookie {} running but not configured".format(nodeid, flowid, bscid, cookie)
                    error_found = True
                elif version != _get_flow_version(config_nodes[nodeid]['bscids'][bscid]):
                    print "WARNING: (operational) node {} flowid {} bscid {} cookie {} config version is different. Operational version {}, config version {}".format(nodeid, flowid, bscid, cookie,version,_get_flow_version(config_nodes[nodeid]['bscids'][bscid]))
                    error_found = True

                if nodeid not in switch_flows_groups or bscid not in switch_flows_groups[nodeid]['bscids']:
                    print "ERROR: (operational) node {} flowid {} bscid {} cookie {} in operational store but not in switch".format(nodeid, flowid, bscid, cookie)
                    error_found = True
                elif version != _get_flow_version(switch_flows_groups[nodeid]['bscids'][bscid]):
                    print "WARNING: (operational) node {} flowid {} bscid {} cookie {} switch version is different. Operational version {}, switch version {}".format(nodeid, flowid, bscid, cookie,version,_get_flow_version(switch_flows_groups[nodeid]['bscids'][bscid]))
                    error_found = True

            for groupid in node['groups']:
                if nodeid not in config_nodes or groupid not in config_nodes[nodeid]['groups']:
                    print "ERROR: (operational) node {} group {} running but not configured".format(nodeid, groupid)
                    error_found = True
                if nodeid not in switch_flows_groups or groupid not in switch_flows_groups[nodeid]['groups']:
                    print "ERROR: (operational) node {} group {} running but not in switch".format(nodeid, groupid)
                    error_found = True

        for nodeid in switch_flows_groups:
            node = switch_flows_groups[nodeid]

            for bscid, cookie in node['bscids'].iteritems():
                version = _get_flow_version(cookie)

                if nodeid not in config_nodes or bscid not in config_nodes[nodeid]['bscids']:
                    print "ERROR: (switch) node {} cookie {} bscid {} running in switch but not configured".format(nodeid, cookie, bscid)
                    error_found = True
                elif version != _get_flow_version(config_nodes[nodeid]['bscids'][bscid]):
                    print "WARNING: (switch) node {} cookie {} bscid {} switch version is different. Switch version {}, config version {}".format(nodeid, cookie, bscid,version,_get_flow_version(config_nodes[nodeid]['bscids'][bscid]))
                    error_found = True

                if nodeid not in operational_nodes or bscid not in operational_nodes[nodeid]['bscids']:
                    print "ERROR: (switch) node {} cookie {} bscid {} running in switch but not in operational".format(nodeid, cookie, bscid)
                    error_found = True
                elif version != _get_flow_version(operational_nodes[nodeid]['bscids'][bscid]):
                    print "WARNING: (switch) node {} cookie {} bscid {} switch version is different. Switch version {}, operational version {}".format(nodeid, cookie, bscid,version,_get_flow_version(operational_nodes[nodeid]['bscids'][bscid]))
                    error_found = True

            for groupid in node['groups']:
                if nodeid not in config_nodes or groupid not in config_nodes[nodeid]['groups']:
                    print "ERROR: (switch) node {} group {} running in switch but not configured".format(nodeid, groupid)
                    error_found = True

        filename = ".previous_flows_groups.json"
        if check_stats:
            for nodeid in switch_flows_groups:
                node = switch_flows_groups[nodeid]
                if os.path.exists(filename):
                    with open(filename, 'r') as infile:
                        prev_stats = json.load(infile)
                        try:
                            for cookie, flow in node['cookies'].iteritems():
                                if nodeid not in prev_stats or cookie not in prev_stats[nodeid]['cookies']:
                                    continue
                                if int(flow['packets']) < int(prev_stats[nodeid]['cookies'][cookie]['packets']):
                                    print "ERROR: flow w/ cookie {} on node {} had {} packet count before-- now has {}; it may have been reinstalled".format(cookie, nodeid, prev_stats[nodeid]['flows'][cookie]['packets'], flow['packets'])
                                    error_found = True

                            for groupid, group in node['groups'].iteritems():
                                if nodeid not in prev_stats or groupid not in prev_stats[nodeid]['groups']:
                                    continue
                                if int(group['packets']) < int(prev_stats[nodeid]['groups'][groupid]['packets']):
                                    print "ERROR: group {} on node {} had {} packet count before-- now has {}; it may have been reinstalled".format(groupid, nodeid, prev_stats[nodeid]['groups'][groupid]['packets'], group['packets'])
                                    error_found = True

                        except KeyError:
                            print "Current and previous nodes out of sync, overwriting old data. Please try again"
                            break

        with open(filename, 'w') as outfile:
            json.dump(switch_flows_groups, outfile)

        if not error_found:
            print "OK: all flows/groups are in sync for given {} nodes.".format(len(self.switches_openflow_names))
            return True

        return False


    def print_flow_stats(self,filters=None, node_name=None):

        resp = self._http_get(self._get_operational_openflow())
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get openflow information'
            return

        data = json.loads(resp.content)
        if 'nodes' not in data or 'node' not in data['nodes']:
            print 'ERROR: no nodes found while trying to get openflow information'
            return

        for node in data['nodes']['node']:
            nodeid = node['id']
            if not self.containsSwitch(nodeid):
                continue

            if node_name and node['id'] != node_name:
                continue

            tables = node.get('flow-node-inventory:table')
            if tables is None:
                tables = node.get('table')

            if tables is not None:
                for table in tables:
                    tableid = table['id']
                    theflows = table.get('flow')
                    if theflows is not None:
                        for flow in theflows:
                            if not contains_filters(filters,flow['id']):
                                continue

                            flowid = 'node/{}/table/{}/flow/{}'.format(node['id'],tableid, flow['id'])
                            stats = flow.get('flow-statistics')
                            if stats is None:
                                stats = flow.get('opendaylight-flow-statistics:flow-statistics')
                            if stats:
                                print flowid
                                print json.dumps(stats,indent=2)


    def print_group_stats(self,filters=None, node_name=None):

        resp = self._http_get(self._get_operational_openflow())
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get openflow information'
            return

        data = json.loads(resp.content)
        if 'nodes' not in data or 'node' not in data['nodes']:
            print 'ERROR: no nodes found while trying to get openflow information'
            return

        for node in data['nodes']['node']:

            nodeid = node['id']
            if not self.containsSwitch(nodeid):
                continue

            if node_name and node['id'] != node_name:
                continue

            thegroups = node.get('flow-node-inventory:group')
            if thegroups is None:
                thegroups = node.get('group')

            if thegroups is not None:
                for group in thegroups:

                    if 'name' not in group and not contains_filters(filters,group['group-id']):
                        continue
                    if 'name' in group and not contains_filters(filters,group['name']):
                        continue

                    groupid = 'node/{}/group/{}'.format(node['id'], group['group-id'])
                    stats = group.get('group-statistics')
                    if stats is None:
                        stats = group.get('opendaylight-group-statistics:group-statistics')

                    if stats:
                        print groupid
                        print json.dumps(stats,indent=2)


    def print_eline_stats(self, filters=None):

        resp = self._http_get(self._get_config_url() + '/brocade-bsc-eline:elines')
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get openflow information'
            return

        data = json.loads(resp.content)
        if 'elines' not in data or 'eline' not in data['elines'] or data['elines']['eline'] is None:
            return

        for eline in data['elines']['eline']:
            if contains_filters(filters,eline['name']):
                print 'eline: ' + eline['name']
                resp = self._http_post(self._get_operations_url()+'/brocade-bsc-eline:get-stats','{"input":{"name": "'+eline['name']+'"}}')
                print json.dumps(json.loads(resp.content),indent=2)

    def print_eline_summary(self, filters=None):

        resp = self._http_get(self._get_config_url() + '/brocade-bsc-eline:elines')
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get eline information'
            return

        data = json.loads(resp.content)
        if 'elines' not in data or 'eline' not in data['elines'] or data['elines']['eline'] is None:
            return

        for eline in data['elines']['eline']:
            if contains_filters(filters,eline['name']):
                resp = self._http_post(self._get_operations_url()+'/brocade-bsc-eline:get-stats','{"input":{"name": "'+eline['name']+'"}}')
                if resp is None or resp.status_code != 200 or resp.content is None:
                    print 'ERROR: cannot get stats for eline {}'.format(eline['name'])
                    continue

                eline_stats = json.loads(resp.content)
                stats_output = eline_stats.get('output')
                state = None if not stats_output else stats_output.get('state')
                successful = bool(state.get('successful')) if state and 'successful' in state else False
                error_msg = state.get('message') if state else ''
                code = state.get('code') if state else -1
                msg = 'state:OK' if successful else 'state: KO code:{} message:{}'.format(code,error_msg)
                print "eline: '" + eline['name'] + "' " + msg

                resp = self._http_get(self._get_config_url() + '/brocade-bsc-path:paths/path/{}'.format(eline['path-name']))
                if resp is None or resp.status_code != 200 or resp.content is None:
                    print 'ERROR: cannot get path for eline {}'.format(eline['name'])
                    continue

                # get endpoint names
                eline_path = json.loads(resp.content)
                e1 = eline_path['path'][0]['endpoint1']
                e1Name = e1['node'] if e1 and 'node' in e1 else ''
                e2 = eline_path['path'][0]['endpoint2']
                e2Name = e2['node'] if e2 and 'node' in e1 else ''

                # get endpoint ingress/egress packets
                e1s = stats_output.get('endpoint1') if stats_output else None
                e1si =  e1s.get('ingress') if e1s else None
                e1sip =  e1si.get('statistics').get('packet-count') if e1si and e1si.get('statistics') else -1
                e1se =  e1s.get('egress') if e1s else None
                e1sep =  e1se.get('statistics').get('packet-count') if e1se and e1se.get('statistics') else -1
                e2s = stats_output.get('endpoint2') if stats_output else None
                e2si =  e2s.get('ingress') if e2s else None
                e2sip =  e2si.get('statistics').get('packet-count') if e2si and e2si.get('statistics') else -1
                e2se =  e2s.get('egress') if e2s else None
                e2sep =  e2se.get('statistics').get('packet-count') if e2se and e2se.get('statistics') else -1

                print "\tfrom '{}' (packets {}) to '{}' (packets {})".format(e1Name, e1sip, e2Name, e2sep)
                print "\tfrom '{}' (packets {}) to '{}' (packets {})".format(e2Name, e2sip, e1Name, e1sep)
                print ""


    def print_etree_stats(self, filters=None):

        resp = self._http_get(self._get_config_url() + '/brocade-bsc-etree:etrees')
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get openflow information'
            return

        data = json.loads(resp.content)
        if 'etrees' not in data or 'etree' not in data['etrees'] or data['etrees']['etree'] is None:
            return

        for etree in data['etrees']['etree']:
            if contains_filters(filters,etree['name']):
                print 'etree: ' + etree['name']
                resp = self._http_post(self._get_operations_url()+'/brocade-bsc-etree:get-stats','{"input":{"name": "'+etree['name']+'"}}')
                print json.dumps(json.loads(resp.content),indent=2)


    def print_etree_summary(self, filters=None):

        resp = self._http_get(self._get_config_url() + '/brocade-bsc-etree:etrees')
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get etree information'
            return

        data = json.loads(resp.content)
        if 'etrees' not in data or 'etree' not in data['etrees'] or data['etrees']['etree'] is None:
            return

        for etree in data['etrees']['etree']:
            if contains_filters(filters,etree['name']):

                resp = self._http_post(self._get_operations_url()+'/brocade-bsc-etree:get-stats','{"input":{"name": "'+etree['name']+'"}}')
                if resp is None or resp.status_code != 200 or resp.content is None:
                    print 'ERROR: cannot get stats for etree {}'.format(etree['name'])
                    continue

                etree_stats = json.loads(resp.content)
                stats_output = etree_stats.get('output')
                state = None if not stats_output else stats_output.get('state')
                successful = bool(state.get('successful')) if state and 'successful' in state else False
                error_msg = state.get('message') if state else ''
                code = state.get('code') if state else -1
                msg = 'state:OK' if successful else 'state: KO code:{} message:{}'.format(code,error_msg)
                print "etree: '" + etree['name'] + "' " + msg

                resp = self._http_get(self._get_config_url() + '/brocade-bsc-tree-path:treepaths/treepath/{}'.format(etree['treepath-name']))
                if resp is None or resp.status_code != 200 or resp.content is None:
                    print 'ERROR: cannot get treepath for etree {}'.format(etree['name'])
                    continue

                # get endpoint names
                etree_path = json.loads(resp.content)
                root = etree_path['treepath'][0]['root']
                rootName = root['node'] if root and 'node' in root else ''

                # get root/leaves ingress/egress packets
                ri = stats_output.get('ingress') if stats_output else None
                rip =  ri.get('statistics').get('packet-count') if ri and ri.get('statistics') else -1
                if not stats_output or not stats_output.get('leaf-statistics') or len(stats_output.get('leaf-statistics')) <= 0:
                    print 'ERROR: leaves not found in etree'
                    continue

                for leaf in stats_output.get('leaf-statistics'):
                    leafName = leaf.get('node')
                    leafe =  leaf.get('egress')
                    leafep =  leafe.get('statistics').get('packet-count') if leafe and leafe.get('statistics') else -1
                    print "\tfrom '{}' (packets {}) to '{}' (packets {})".format(rootName, rip, leafName, leafep)

                print ""

    def _get_base_url(self):
        return self.ctrl_protocol + '://' + self.ctrl_ip + ':' + str(self.ctrl_port) + '/restconf'

    def _get_config_url(self):
        return self._get_base_url() + '/config'

    def _get_operational_url(self):
        return self._get_base_url() + '/operational'

    def _get_operations_url(self):
        return self._get_base_url() + '/operations'

    def _get_config_openflow(self):
        return self._get_config_url() + '/opendaylight-inventory:nodes'

    def _get_operational_openflow(self):
        return self._get_operational_url() + '/opendaylight-inventory:nodes'

    def _get_config_flow_url(self, node, table, flow):
        return self._get_config_openflow() + '/node/{}/table/{}/flow/{}'.format(node, str(table), flow)

    def _get_operational_flow_url(self, node, table, flow):
        return self._get_operational_openflow() + '/node/{}/table/{}/flow/{}'.format(node, str(table), flow)

    def _get_config_group_url(self, node, group):
        return self._get_config_openflow() + '/node/{}/group/{}'.format(node, str(group))

    def _get_operational_group_url(self, node, group):
        return self._get_operational_openflow() + '/node/{}/group/{}'.format(node, str(group))

    def _http_get(self, url):
        return requests.get(url,
                            auth=HTTPBasicAuth(self.ctrl_user,
                                               self.ctrl_password),
                            headers=_DEFAULT_HEADERS,
                            timeout=self.ctrl_timeout,
                            verify=False)

    def _http_post(self, url, data):
        return requests.post(url,
                             auth=HTTPBasicAuth(self.ctrl_user,
                                                self.ctrl_password),
                             data=data, headers=_DEFAULT_HEADERS,
                             timeout=self.ctrl_timeout,
                             verify=False)

    def _http_put(self, url, data):
        return requests.put(url,
                            auth=HTTPBasicAuth(self.ctrl_user,
                                               self.ctrl_password),
                            data=data, headers=_DEFAULT_HEADERS,
                            timeout=self.ctrl_timeout,
                            verify=False)

    def _http_delete(self, url):
        return requests.delete(url,
                               auth=HTTPBasicAuth(self.ctrl_user,
                                                  self.ctrl_password),
                               headers=_DEFAULT_HEADERS,
                               timeout=self.ctrl_timeout,
                               verify=False)

    def _get_node_cluster_status(self, openflow_name):
        resp = self._http_get(self._get_operational_url() +
                              '/entity-owners:entity-owners/entity-type/org.opendaylight.mdsal.ServiceEntityType/entity/%2Fodl-general-entity%3Aentity%5Bodl-general-entity%3Aname%3D%27{}%27%5D'.format(openflow_name))
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            entity = data.get('entity')
            if entity and len(entity) > 0:
                return entity[0]

    def _get_node_cluster_owner(self, openflow_name):
        entity = self._get_node_cluster_status(openflow_name)
        if entity:
            return entity.get('owner')

    def _get_nodes_and_links(self, topology_name):
        nodelist = {}
        linklist = {}
        resp = self._http_get(self._get_operational_url() +
                              '/network-topology:network-topology/topology/{}'.format(topology_name))
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            topology = data.get('topology')
            nodes = None
            if topology is not None and len(topology) > 0:
                nodes = topology[0].get('node')
                if nodes is not None:
                    for node in nodes:
                        if unicode(node['node-id']).startswith(unicode('host')):
                            continue
                        if not self.containsSwitch(node['node-id']):
                            continue
                        nodelist[node['node-id']] = node
                links = topology[0].get('link')
                if links is not None:
                    for link in links:
                        if link['source']['source-node'].startswith('host'):
                            continue
                        if link['destination']['dest-node'].startswith('host'):
                            continue
                        if not self.containsSwitch(link['source']['source-node']):
                            continue
                        if not self.containsSwitch(link['destination']['dest-node']):
                            continue
                        linklist[link['link-id']] = link

        print "Topology {} has {} nodes and {} links. {} ".format(topology_name, len(nodelist), len(linklist), nodelist.keys())
        return nodelist, linklist

    def _get_flow_group(self, url, prefix=None):
        nodes = {}

        # print "Checking if all flows and groups in configuration data store are present in operational data store ..."
        resp = self._http_get(url)
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'no data found while trying to get openflow information'
            return nodes

        data = json.loads(resp.content)
        if 'nodes' not in data or 'node' not in data['nodes']:
            print 'no nodes found while trying to get openflow information'
            return nodes

        for node in data['nodes']['node']:
            nodeid = node['id']
            if not self.containsSwitch(nodeid):
                continue

            flows = {}
            groups = {}
            cookies = {}
            bscids = {}
            nodes[nodeid] = {
                'flows': flows,
                'groups': groups,
                'cookies': cookies,
                'bscids': bscids
            }

            thegroups = node.get('flow-node-inventory:group')
            if thegroups is None:
                thegroups = node.get('group')

            if thegroups is not None:
                for group in thegroups:
                    groups[group['group-id']] = group

            tables = node.get('flow-node-inventory:table')
            if tables is None:
                tables = node.get('table')

            if tables is not None:
                for table in tables:
                    tableid = table['id']
                    theflows = table.get('flow')
                    if theflows is not None:
                        for flow in theflows:
                            flowid = 'table/{}/flow/{}'.format(tableid, flow['id'])
                            cookie = flow.get('cookie')
                            if prefix is not None and cookie:
                                if cookie >> 56 != prefix:
                                    continue
                            flows[flowid] = flow
                            if not cookie:
                                continue
                            if cookie in cookies:
                                print "ERROR: unexpected duplicated cookie {}, between {} and {}".format(cookie, flowid, cookies[cookie])
                            else:
                                cookies[cookie] = flowid
                                bscid = _get_flow_bscid(cookie)
                                bscids[bscid] = cookie

        return nodes

    def _get_calculated_flows_groups(self):
        srnodes = {}
        resp = self._http_get(self._get_operational_url() + '/network-topology:network-topology/topology/flow:1:sr')
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            topology = data.get('topology')
            nodes = None
            if topology is not None and len(topology) > 0:
                nodes = topology[0].get('node')
                if nodes is not None:
                    for node in nodes:
                        nodeid = node['node-id']
                        if not self.containsSwitch(nodeid):
                            continue
                        srnodes[nodeid] = {'groups': [], 'flows': []}
                        brocadesr = node.get('brocade-bsc-sr:sr')
                        groups = None
                        if brocadesr is not None:
                            self.append_calculated_groups(srnodes, brocadesr.get('calculated-groups'))
                            self.append_calculated_flows(srnodes, brocadesr.get('calculated-flows'))

        resp = self._http_get(self._get_operational_url() + '/brocade-bsc-path:paths')
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('paths') is not None:
                paths = data.get('paths')
                if paths.get('path') is not None:
                    for path in paths.get('path'):
                        self.append_calculated_flows(srnodes, path.get('calculated-flows'))


        resp = self._http_get(self._get_operational_url() + '/brocade-bsc-eline:elines')
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('elines') is not None:
                elines = data.get('elines')
                if elines.get('eline') is not None:
                    for eline in elines.get('eline'):
                        self.append_calculated_flows(srnodes, eline.get('calculated-flows'))


        resp = self._http_get(self._get_operational_url() + '/brocade-bsc-tree-path:treepaths')
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('treepaths') is not None:
                paths = data.get('treepaths')
                if paths.get('treepath') is not None:
                    for path in paths.get('treepath'):
                        self.append_calculated_flows(srnodes, path.get('calculated-flows'))
                        self.append_calculated_groups(srnodes, path.get('calculated-groups'))

        resp = self._http_get(self._get_operational_url() + '/brocade-bsc-etree:etrees')
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('etrees') is not None:
                etrees = data.get('etrees')
                if etrees.get('etree') is not None:
                    for etree in etrees.get('etree'):
                        self.append_calculated_flows(srnodes, etree.get('calculated-flows'))
                        self.append_calculated_groups(srnodes, etree.get('calculated-groups'))

        resp = self._http_get(self._get_operational_url() + '/brocade-bsc-path-mpls:mpls-nodes')
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            mpls_nodes = data.get('mpls-nodes')
            if mpls_nodes is not None:
                self.append_calculated_flow_nodes(srnodes, mpls_nodes.get('calculated-flow-nodes'))

        resp = self._http_get(self._get_operational_url() + '/brocade-bsc-eline-mpls:eline-nodes')
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            mpls_nodes = data.get('eline-nodes')
            if mpls_nodes is not None:
                self.append_calculated_flow_nodes(srnodes, mpls_nodes.get('calculated-flow-nodes'))

        resp = self._http_get(self._get_operational_url() + '/brocade-bsc-etree-sr:etree-nodes')
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            mpls_nodes = data.get('etree-nodes')
            if mpls_nodes is not None:
                self.append_calculated_flow_nodes(srnodes, mpls_nodes.get('calculated-flow-nodes'))

        return srnodes

    def append_calculated_flow_nodes(self, nodes, cnodes):
        if cnodes is not None:
            cnodes = cnodes.get('calculated-flow-node')
            if cnodes is not None:
                for cnode in cnodes:
                    self.append_calculated_flows(nodes, cnode.get('calculated-flows'))

    def append_calculated_flows(self, nodes, flows):
        if flows is not None:
            cflows = flows.get('calculated-flow')
            if cflows is not None:
                for flow in cflows:
                    flowid = 'table/{}/flow/{}'.format(flow['table-id'], flow['flow-name'])
                    nodeid = flow['node-id']
                    if not self.containsSwitch(nodeid):
                        continue
                    if nodeid not in nodes:
                        nodes[nodeid] = {'groups': [], 'flows': []}
                    nodes[nodeid]['flows'].append(flowid)

    def append_calculated_groups(self, nodes, groups):
        if groups is not None:
            cgroups = groups.get('calculated-group')
            if cgroups is not None:
                for group in cgroups:
                    nodeid = group['node-id']
                    if nodeid not in nodes:
                        nodes[nodeid] = {'groups': [], 'flows': []}
                    nodes[nodeid]['groups'].append(group['group-id'])


def exists_bridge(name):
    try:
        grepOut = subprocess.check_output("sudo ovs-vsctl br-exists {}".format(name), shell=True)
        return True
    except subprocess.CalledProcessError as grepexc:
        return False

def compare_dictionaries(dict1, dict2):
    if dict1 is None:
        return dict2 is None
    if dict2 is None:
        return False
    if type(dict1) != type(dict2):
        return False
    if type(dict1) is not dict and type(dict1) is not list:
        return dict1 == dict2
    if len(dict1) != len(dict2):
        return False
    if type(dict1) is list:
        for el in dict1:
            if el not in dict2:
                return False
        return True
    # is dict
    for key in dict1:
        if key not in dict2:
            return False
        if not compare_dictionaries(dict1[key], dict2[key]):
            return False
    return True
