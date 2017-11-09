"""Controller

This module contains the primitives to access controller information.

"""

# support both version of REST API
LUMINA_FLOW_MANAGER_PREFIX = 'lumina-flowmanager-'
BROCADE_FLOW_MANAGER_PREFIX = 'brocade-bsc'

DEFAULT_HEADERS = {
    'content-type': 'application/json',
    'accept': 'application/json'
}


class Controller(object):

    def __init__(self, props, controller_vip):
        utils.check_mandatory_values(props, ['name'])
        self.props = props

        self.name = props.get('name')
        self.protocol = 'http' if not props.get('protocol') else props['protocol']
        self.vip = props.get['vip'] if props.get('vip') else controller_vip
        self.ip = '127.0.0.1' if not ctrl.get('ip') else ctrl['ip']
        self.port = '8181' if not ctrl.get('port') else int(ctrl['port'])
        self.user = 'admin' if not ctrl.get('user') else ctrl['user']
        self.password = 'admin' if not ctrl.get('password') else ctrl['password']
        self.timeout = 60 if not ctrl.get('timeout') else int(ctrl['timeout'])
        self.sshuser = 'root' if not ctrl.get('sshuser') else ctrl['sshuser']
        self.sshpassword = 'lumina' if not ctrl.get('sshpassword') else ctrl['sshpassword']
        self.sshport = '22' if not ctrl.get('sshport') else ctrl['sshport']

        # if IP address and user is not given
        # then we need to assume OVS is running locally
        self.execute_local = not props.get('ip') and not props.get('sshuser')
        self.execute_local = True if self.ip == '127.0.0.1' else self.execute_local

        REQUEST_URL = '/' + LUMINA_FLOW_MANAGER_PREFIX + 'path:paths'
        resp = self._http_get(self.get_config_url() + REQUEST_URL)
        if resp is not None and resp.status_code == 400:
            self.brocade = True
            self.lumina = False
        else:
            self.brocade = False
            self.lumina = True

    def get_base_url(self, use_vip=False):
        return self.protocol + '://' + self.vip if use_vip and self.vip else self.ip + ':' + str(self.port) + '/restconf'

    def get_config_url(self):
        return self.get_base_url() + '/config'

    def get_operational_url(self):
        return self.get_base_url() + '/operational'

    def get_operations_url(self):
        return self.get_base_url() + '/operations'

    def get_config_fm_url(self, name):
        return self.get_config_url() + '/' + LUMINA_FLOW_MANAGER_PREFIX if self.lumina else BROCADE_FLOW_MANAGER_PREFIX + name

    def get_operational_fm_url(self, name):
        return self.get_operational_url() + '/' + LUMINA_FLOW_MANAGER_PREFIX if self.lumina else BROCADE_FLOW_MANAGER_PREFIX + name

    def get_operations_fm_url(self, name):
        return self.get_operations_url() + '/' + LUMINA_FLOW_MANAGER_PREFIX if self.lumina else BROCADE_FLOW_MANAGER_PREFIX + name

    def get_config_openflow(self):
        return self.get_config_url() + '/opendaylight-inventory:nodes'

    def get_operational_openflow(self):
        return self.get_operational_url() + '/opendaylight-inventory:nodes'

    def get_config_flow_url(self, node, table, flow):
        return self.get_config_openflow() + '/node/{}/table/{}/flow/{}'.format(node, str(table), flow)

    def get_operational_flow_url(self, node, table, flow):
        return self.get_operational_openflow() + '/node/{}/table/{}/flow/{}'.format(node, str(table), flow)

    def get_config_group_url(self, node, group):
        return self.get_config_openflow() + '/node/{}/group/{}'.format(node, str(group))

    def get_operational_group_url(self, node, group):
        return self.get_operational_openflow() + '/node/{}/group/{}'.format(node, str(group))

    def http_get(self, url):
        return requests.get(url,
                            auth=HTTPBasicAuth(self.user,
                                               self.password),
                            headers=DEFAULT_HEADERS,
                            timeout=self.timeout,
                            verify=False)

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

     def reboot(self, seconds=0):
        if not self.execute_command_controller('sudo service-' + 'lsc' if self.lumina else 'brcd' + ' stop' ):
            return False
        if int(seconds) > 0:
            time.sleep(int(seconds))
        if not self.execute_command_controller('sudo service-' + 'lsc' if self.lumina else 'brcd' + ' start' ):
            return False

     def reboot_server(self):
         self.execute_command_controller('sudo reboot'):

     def isolate(self, seconds=0):
        if 'isolate_cmd' not in self.props or len(self.props['isolate_cmd']) <=0 or 'isolate_undo_cmd' not in self.props or len(self.props['isolate_undo_cmd']) <=0:
         raise Exception("ERROR: isolate commands not found in controller {}".format(self.name)

        for command in controller['isolate_cmd']:
         if not self.execute_command_controller(command):
             return False
        if int(seconds) > 0:
            time.sleep(int(seconds))
        for command in controller['isolate_undo_cmd']:
         if not self.execute_command_controller(command):
             return False

        return True
