"""Controller

This module contains the primitives to access controller information.

"""
import logging
import requests
import json
from flowmanager.ssh import SSH
from requests.auth import HTTPBasicAuth
from flowmanager.utils import contains_filters
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

    def get_eline_url(self):
        return self.get_operations_url() + '/' + 'brocade-bsc-eline:get-stats'

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
                                logging.info('\n%s\n%s', flowid,
                                             json.dumps(stats, indent=2))

    def get_group_stats(self, filters=None, node_name=None):

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

            thegroups = node.get('flow-node-inventory:group')
            if thegroups is None:
                thegroups = node.get('group')

            if thegroups is not None:
                for group in thegroups:

                    if 'name' not in group and not contains_filters(filters, group['group-id']):
                        continue
                    if 'name' in group and not contains_filters(filters, group['name']):
                        continue

                    groupid = 'node/{}/group/{}'.format(
                        node['id'], group['group-id'])
                    stats = group.get('group-statistics')
                    if stats is None:
                        stats = group.get(
                            'opendaylight-group-statistics:group-statistics')

                    if stats:
                        logging.info(groupid)
                        logging.info(json.dumps(stats, indent=2))

    def get_eline_stats(self, filters=None):
        logging.debug(self.get_eline_url())
        resp = self.http_get(self.get_eline_url())
        if resp is None or resp.status_code != 200 or resp.content is None:
            logging.error(
                'no data found while trying to get openflow information %s', resp.status_code)
            return

        data = json.loads(resp.content)
        if 'elines' not in data or 'eline' not in data['elines'] or data['elines']['eline'] is None:
            return

        for eline in data['elines']['eline']:
            if contains_filters(filters, eline['name']):
                print 'eline: ' + eline['name']
                resp = self._http_post(self._get_operations_url(
                ) + REST_URL_ELINE_STATS, '{"input":{"name": "' + eline['name'] + '"}}')
                print json.dumps(json.loads(resp.content), indent=2)

    def get_eline_summary(self, filters=None):

        resp = self._http_get(self._get_config_url() + REST_URL_ELINE)
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get eline information'
            return

        data = json.loads(resp.content)
        if 'elines' not in data or 'eline' not in data['elines'] or data['elines']['eline'] is None:
            return

        for eline in data['elines']['eline']:
            if contains_filters(filters, eline['name']):
                resp = self._http_post(self._get_operations_url(
                ) + REST_URL_ELINE_STATS, '{"input":{"name": "' + eline['name'] + '"}}')
                if resp is None or resp.status_code != 200 or resp.content is None:
                    print 'ERROR: cannot get stats for eline {}'.format(eline['name'])
                    continue

                eline_stats = json.loads(resp.content)
                stats_output = eline_stats.get('output')
                state = None if not stats_output else stats_output.get('state')
                successful = bool(state.get('successful')
                                  ) if state and 'successful' in state else False
                error_msg = state.get('message') if state else ''
                code = state.get('code') if state else -1
                msg = 'state:OK' if successful else 'state: KO code:{} message:{}'.format(
                    code, error_msg)
                print "eline: '" + eline['name'] + "' " + msg

                resp = self._http_get(self._get_config_url(
                ) + REST_URL_PATH + '/path/{}'.format(eline['path-name']))
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
                e1si = e1s.get('ingress') if e1s else None
                e1sip = e1si.get('statistics').get(
                    'packet-count') if e1si and e1si.get('statistics') else -1
                e1se = e1s.get('egress') if e1s else None
                e1sep = e1se.get('statistics').get(
                    'packet-count') if e1se and e1se.get('statistics') else -1
                e2s = stats_output.get('endpoint2') if stats_output else None
                e2si = e2s.get('ingress') if e2s else None
                e2sip = e2si.get('statistics').get(
                    'packet-count') if e2si and e2si.get('statistics') else -1
                e2se = e2s.get('egress') if e2s else None
                e2sep = e2se.get('statistics').get(
                    'packet-count') if e2se and e2se.get('statistics') else -1

                print "\tfrom '{}' (packets {}) to '{}' (packets {})".format(e1Name, e1sip, e2Name, e2sep)
                print "\tfrom '{}' (packets {}) to '{}' (packets {})".format(e2Name, e2sip, e1Name, e1sep)
                print ""

    def get_etree_stats(self, filters=None):

        resp = self._http_get(self._get_config_url() + REST_URL_ETREE)
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get openflow information'
            return

        data = json.loads(resp.content)
        if 'etrees' not in data or 'etree' not in data['etrees'] or data['etrees']['etree'] is None:
            return

        for etree in data['etrees']['etree']:
            if contains_filters(filters, etree['name']):
                print 'etree: ' + etree['name']
                resp = self._http_post(self._get_operations_url(
                ) + REST_URL_ETREE_STATS, '{"input":{"name": "' + etree['name'] + '"}}')
                print json.dumps(json.loads(resp.content), indent=2)

    def get_etree_summary(self, filters=None):

        resp = self._http_get(self._get_config_url() + REST_URL_ETREE)
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get etree information'
            return

        data = json.loads(resp.content)
        if 'etrees' not in data or 'etree' not in data['etrees'] or data['etrees']['etree'] is None:
            return

        for etree in data['etrees']['etree']:
            if contains_filters(filters, etree['name']):

                resp = self._http_post(self._get_operations_url(
                ) + REST_URL_ETREE_STATS, '{"input":{"name": "' + etree['name'] + '"}}')
                if resp is None or resp.status_code != 200 or resp.content is None:
                    print 'ERROR: cannot get stats for etree {}'.format(etree['name'])
                    continue

                etree_stats = json.loads(resp.content)
                stats_output = etree_stats.get('output')
                state = None if not stats_output else stats_output.get('state')
                successful = bool(state.get('successful')
                                  ) if state and 'successful' in state else False
                error_msg = state.get('message') if state else ''
                code = state.get('code') if state else -1
                msg = 'state:OK' if successful else 'state: KO code:{} message:{}'.format(
                    code, error_msg)
                print "etree: '" + etree['name'] + "' " + msg

                resp = self._http_get(self._get_config_url(
                ) + REST_URL_TREEPATH + '/treepath/{}'.format(etree['treepath-name']))
                if resp is None or resp.status_code != 200 or resp.content is None:
                    print 'ERROR: cannot get treepath for etree {}'.format(etree['name'])
                    continue

                # get endpoint names
                etree_path = json.loads(resp.content)
                root = etree_path['treepath'][0]['root']
                rootName = root['node'] if root and 'node' in root else ''

                # get root/leaves ingress/egress packets
                ri = stats_output.get('ingress') if stats_output else None
                rip = ri.get('statistics').get(
                    'packet-count') if ri and ri.get('statistics') else -1
                if not stats_output or not stats_output.get('leaf-statistics') or len(stats_output.get('leaf-statistics')) <= 0:
                    print 'ERROR: leaves not found in etree'
                    continue

                for leaf in stats_output.get('leaf-statistics'):
                    leafName = leaf.get('node')
                    leafe = leaf.get('egress')
                    leafep = leafe.get('statistics').get(
                        'packet-count') if leafe and leafe.get('statistics') else -1
                    print "\tfrom '{}' (packets {}) to '{}' (packets {})".format(rootName, rip, leafName, leafep)

                print ""

    def execute_command_controller(self, command):
        SSHobj = SSH(self.ip, self.sshuser, self.sshport, self.sshpassword)
        return SSHobj.execute_single_command(command)

    def reboot(self, seconds=0):
        if not self.execute_command_controller('sudo service ' + ('lsc' if self.lumina else 'brcd-bsc') + ' stop'):
            return False
        if int(seconds) > 0:
            time.sleep(int(seconds))
        if not self.execute_command_controller('sudo service ' + ('lsc' if self.lumina else 'brcd-bsc') + ' start'):
            return False
        return True

    # def reboot_server(self):
    #     return self.execute_command_controller('sudo reboot')

    def isolate(self, seconds=0):
        raise Exception('to be implemented')
        # if 'isolate_cmd' not in self.props or len(self.props['isolate_cmd']) <= 0 or 'isolate_undo_cmd' not in self.props or len(self.props['isolate_undo_cmd']) <= 0:
        #     raise Exception("ERROR: isolate commands not found in controller {}".format(self.name)

        # for command in controller['isolate_cmd']:
        #     if not self.execute_command_controller(command):
        #         return False
        # if int(seconds) > 0:
        #     time.sleep(int(seconds))
        # for command in controller['isolate_undo_cmd']:
        #     if not self.execute_command_controller(command):
        #         return False
        # return True
