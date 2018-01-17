"""Controller

This module contains the primitives to access controller information.

"""
import logging
import requests
import json
from flowmanager.ssh import SSH
from requests.auth import HTTPBasicAuth

from flowmanager.utils import check_mandatory_values

# support both version of REST API
LUMINA_FLOW_MANAGER_PREFIX = 'lumina-flowmanager-'
BROCADE_FLOW_MANAGER_PREFIX = 'brocade-bsc-'

DEFAULT_HEADERS = {
    'content-type': 'application/json',
    'accept': 'application/json'
}


class Controller(object):

    def __init__(self, props, controller_vip):
        check_mandatory_values(props, ['name'])
        self.props = props

        self.name = props.get('name')
        self.protocol = 'http' if not props.get(
            'protocol') else props['protocol']
        self.vip = props.get['vip'] if props.get('vip') else controller_vip
        self.ip = '127.0.0.1' if not props.get('ip') else props['ip']
        self.port = '8181' if not props.get('port') else int(props['port'])
        self.user = 'admin' if not props.get('user') else props['user']
        self.password = 'admin' if not props.get(
            'password') else props['password']
        self.timeout = 60 if not props.get(
            'timeout') else int(props['timeout'])
        self.sshuser = 'root' if not props.get('sshuser') else props['sshuser']
        self.sshpassword = 'lumina' if not props.get(
            'sshpassword') else props['sshpassword']
        self.sshport = '22' if not props.get('sshport') else props['sshport']

        # if IP address and user is not given
        # then we need to assume OVS is running locally
        self.execute_local = not props.get('ip') and not props.get('sshuser')
        self.execute_local = True if self.ip == '127.0.0.1' else self.execute_local

        self.fm_prefix = None
        self.lumina = False

    def is_running(self):
        raise Exception("to implement. check if process is up")

    def is_sync(self):
        url = self.get_base_url() + "/jolokia/read/org.opendaylight.controller:Category=ShardManager,name=shard-manager-operational,type=DistributedOperationalDatastore"
        resp = self.http_get(url)
        if resp is not None or resp.status_code != 200 or not resp.content:
            return False

        data = json.loads(resp.content)
        if not data or 'value' not in data or 'SyncStatus' not in data['value'] or not data['value']['SyncStatus']:
            return False

        return True

    def is_lumina(self):
        self.get_fm_prefix() == LUMINA_FLOW_MANAGER_PREFIX

    def is_brocade(self):
        self.get_fm_prefix() == BROCADE_FLOW_MANAGER_PREFIX

    def get_fm_prefix(self):
        if not self.fm_prefix:
            logging.debug("CONTROLLER: checking the the right prefix")
            self.fm_prefix = BROCADE_FLOW_MANAGER_PREFIX
            REQUEST_URL = '/' + LUMINA_FLOW_MANAGER_PREFIX + 'path:paths'
            resp = self.http_get(self.get_config_url() + REQUEST_URL)
            if resp is not None and resp.status_code == 400:
                self.fm_prefix = BROCADE_FLOW_MANAGER_PREFIX
            else:
                self.fm_prefix = LUMINA_FLOW_MANAGER_PREFIX

            logging.debug("CONTROLLER: setting prefix to %s", self.fm_prefix)
        return self.fm_prefix

    def get_base_url(self, use_vip=False):
        return self.protocol + '://' + (self.vip if use_vip and self.vip else self.ip) + ':' + str(self.port)

    def get_base_url_restconf(self, use_vip=False):
        return self.get_base_url() + '/restconf'

    def get_config_url(self):
        return self.get_base_url_restconf() + '/config'

    def get_operational_url(self):
        return self.get_base_url_restconf() + '/operational'

    def get_operations_url(self):
        return self.get_base_url_restconf() + '/operations'

    def get_operational_openflow(self):
        return self.get_operational_url() + '/opendaylight-inventory:nodes'

    def get_container_fm(self, name):
        return self.get_fm_prefix() + name

    def get_config_fm_url(self, name):
        return self.get_config_url() + '/' + self.get_fm_prefix() + name

    def get_operational_fm_url(self, name):
        return self.get_operational_url() + '/' + self.get_fm_prefix() + name

    def get_operations_fm_url(self, name):
        return self.get_operations_url() + '/' + self.get_fm_prefix() + name

    def http_get(self, url):
        try:
            result = requests.get(url,
                                  auth=HTTPBasicAuth(self.user, self.password),
                                  headers=DEFAULT_HEADERS,
                                  timeout=self.timeout,
                                  verify=False)
            return result
        except requests.exceptions.ConnectionError as errc:
            logging.error("%s", errc)

    def http_post(self, url, data):
        return requests.post(url,
                             auth=HTTPBasicAuth(self.user,
                                                self.password),
                             data=data, headers=DEFAULT_HEADERS,
                             timeout=self.timeout,
                             verify=False)

    def http_put(self, url, data):
        return requests.put(url,
                            auth=HTTPBasicAuth(self.user,
                                               self.password),
                            data=data, headers=DEFAULT_HEADERS,
                            timeout=self.timeout,
                            verify=False)

    def http_delete(self, url):
        return requests.delete(url,
                               auth=HTTPBasicAuth(self.user,
                                                  self.password),
                               headers=DEFAULT_HEADERS,
                               timeout=self.timeout,
                               verify=False)

    def get_flow_stats(self, filters=None, node_name=None):
        resp = self.http_get(self.get_operational_openflow())
        if resp is None or resp.status_code != 200 or resp.content is None:
            logging.error(
                'no data found while trying to get openflow information')
            return

        data = json.loads(resp.content)
        if 'nodes' not in data or 'node' not in data['nodes']:
            logging.error(
                'no nodes found while trying to get openflow information')
            return

        for node in data['nodes']['node']:
            nodeid = node['id']
            # if not self.containsSwitch(nodeid):
            # continue

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
                            if not contains_filters(filters, flow['id']):
                                continue

                            flowid = 'node/{}/table/{}/flow/{}'.format(
                                node['id'], tableid, flow['id'])
                            stats = flow.get('flow-statistics')
                            if stats is None:
                                stats = flow.get(
                                    'opendaylight-flow-statistics:flow-statistics')
                            if stats:
                                print flowid
                                print json.dumps(stats, indent=2)

    def execute_command_controller(self, command):
        SSHobj = SSH(self.ip, self.sshuser, self.sshport, self.sshpassword)
        SSHobj.execute_single_command(command)

    def reboot(self, seconds=0):
        if not self.execute_command_controller('sudo service-' + ('lsc' if self.lumina else 'brcd') + ' stop'):
            return False
        if int(seconds) > 0:
            time.sleep(int(seconds))
        if not self.execute_command_controller('sudo service-' + ('lsc' if self.lumina else 'brcd') + ' start'):
            return False
        return True

    # def reboot_server(self):
    #     return self.execute_command_controller('sudo reboot')

    # def isolate(self, seconds=0):
    #     if 'isolate_cmd' not in self.props or len(self.props['isolate_cmd']) <= 0 or 'isolate_undo_cmd' not in self.props or len(self.props['isolate_undo_cmd']) <= 0:
    #         raise Exception("ERROR: isolate commands not found in controller {}".format(self.name)

    #     for command in controller['isolate_cmd']:
    #         if not self.execute_command_controller(command):
    #             return False
    #     if int(seconds) > 0:
    #         time.sleep(int(seconds))
    #     for command in controller['isolate_undo_cmd']:
    #         if not self.execute_command_controller(command):
    #             return False
    #     return True
