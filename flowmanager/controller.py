"""Controller

This module contains the primitives to access controller information.

"""

# Define all URL values
REST_CONTAINER_PREFIX = 'lumina-flowmanager-'
REST_URL_PREFIX = '/' + REST_CONTAINER_PREFIX

REST_URL_ELINE = REST_URL_PREFIX + 'eline:elines'
REST_URL_ELINE_STATS = REST_URL_PREFIX + 'eline:get-stats'
REST_URL_ELINE_MPLS_NODES = REST_URL_PREFIX + 'eline-mpls:eline-nodes'

REST_URL_PATH = REST_URL_PREFIX + 'path:paths'
REST_URL_PATH_MPLS_NODES = REST_URL_PREFIX + 'path-mpls:mpls-nodes'

REST_URL_ETREE = REST_URL_PREFIX + 'etree:etrees'
REST_URL_ETREE_STATS = REST_URL_PREFIX + 'etree:get-stats'
REST_URL_ETREE_SR_NODES = REST_URL_PREFIX + 'etree-sr:etree-nodes'

REST_URL_TREEPATH = REST_URL_PREFIX + 'tree-path:treepaths'

REST_CONTAINER_SR = REST_CONTAINER_PREFIX + 'sr:sr'

class Controller(object):

	def __init__(self, props):
		#TODO

    def execute_command_controller(self, name, command):
        ctrl = self.controllers_name.get(name)
        if not ctrl:
            print "ERROR: {} controller does not exists".format(name)
            return False

        print "INFO: executing command {} in controller {} with ip {}".format(command, name, ctrl['ip'])
        sshuser = ctrl.get('sshuser')
        sshpassword = ctrl.get('sshpassword')
        sshport = ctrl.get('sshport')

        target = "{}@{}".format(sshuser,ctrl['ip']) if sshuser else ctrl['ip']
        port = sshport if sshport else 22

        cmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p {} {} '{}'".format(port, target, command)
        if sshpassword:
            child = pexpect.spawn(cmd)
            i = child.expect([pexpect.TIMEOUT, unicode('(?i)password')])
            if i == 0:
                print('ERROR: could not connect to controller via SSH. {} port ({})'.format(target, port))
                return False

            child.sendline(sshpassword)
            child.expect([pexpect.TIMEOUT,pexpect.EOF])
            child.close()

        else:
            output = subprocess.check_output(cmd, shell=True)

        return True

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

    def _get_flow_stats_packets(self, flowid):
        stats = self._get_flow_stats(flowid)
        if stats:
            return stats.get('packet-count')
        return -1

    def _get_flow_stats(self, flowid):
        resp = self._http_get(self._get_operational_url() + '/opendaylight-inventory:nodes/{}'.format(flowid))
        if resp is None or resp.status_code != 200 or resp.content is None:
            return None
        data = json.loads(resp.content)
        flowinv = data.get('flow-node-inventory:flow')
        if flowinv is None or len(flowinv) <= 0:
            return None
        return flowinv[0].get('opendaylight-flow-statistics:flow-statistics')

    def _get_group_stats_packets(self, groupid):
        stats = self._get_group_stats(groupid)
        if stats:
            return stats.get('packet-count')
        return -1

    def _get_group_stats(self, groupid):
        resp = self._http_get(self._get_operational_url() + '/opendaylight-inventory:nodes/{}'.format(groupid))
        if resp is None or resp.status_code != 200 or resp.content is None:
            return None
        data = json.loads(resp.content)
        groupinv = data.get('flow-node-inventory:group')
        if groupinv is None or len(groupinv) <= 0:
            return None
        return groupinv[0].get('opendaylight-group-statistics:group-statistics')

    def _get_sr_nodes_paths(self):
        srnodes = {}
        resp = self._http_get(self._get_operational_url() + '/network-topology:network-topology/topology/flow:1:sr')
        if resp is None or resp.status_code != 200 or resp.content is None:
            return None

        data = json.loads(resp.content)
        topology = data.get('topology')
        if topology is None or len(topology) <= 0:
            return None

        nodes = topology[0].get('node')
        if nodes is None:
            return None

        for node in nodes:
            nodeid = node['node-id']
            if not self.containsSwitch(nodeid):
                continue
            brocadesr = node.get(REST_CONTAINER_SR)
            if brocadesr is None:
                continue

            srnodes[nodeid] = {'mpls-label': brocadesr.get('mpls-label'), 'primary-paths': {}}

            cppaths = brocadesr.get('calculated-primary-paths')
            if cppaths is None:
                continue
            cppaths = cppaths.get('calculated-primary-path')
            if cppaths is None:
                continue
            for cppath in cppaths:
                path = {}
                path['group-id'] = 'node/{}/group/{}'.format(nodeid, cppath['group-id'])
                path['flow-id'] = 'node/{}/table/{}/flow/{}'.format(nodeid, cppath['table-id'], cppath['flow-name'])
                srnodes[nodeid]['primary-paths'][cppath['node-id']] = path

            cpaths = brocadesr.get('calculated-paths')
            if cpaths is None:
                continue
            cpaths = cpaths.get('calculated-path')
            if cpaths is None:
                continue

            for cpath in cpaths:
                if cpath.get('primary') is None or cpath['primary'] is not True:
                    continue
                if cpath.get('ordered-hop') is None:
                    continue

                orderedHops = []
                for oh in cpath.get('ordered-hop'):
                    nexthop = oh.get('destination-node')
                    if nexthop is None:
                        continue
                    if nexthop not in orderedHops:
                        orderedHops.append(nexthop)
                srnodes[nodeid]['primary-paths'][cpath['name']]['next-hops']= orderedHops

        return srnodes

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
                        brocadesr = node.get(REST_CONTAINER_SR)
                        groups = None
                        if brocadesr is not None:
                            self.append_calculated_groups(srnodes, brocadesr.get('calculated-groups'))
                            self.append_calculated_flows(srnodes, brocadesr.get('calculated-flows'))

        resp = self._http_get(self._get_operational_url() + REST_URL_PATH)
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('paths') is not None:
                paths = data.get('paths')
                if paths.get('path') is not None:
                    for path in paths.get('path'):
                        self.append_calculated_flows(srnodes, path.get('calculated-flows'))


        resp = self._http_get(self._get_operational_url() + REST_URL_ELINE)
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('elines') is not None:
                elines = data.get('elines')
                if elines.get('eline') is not None:
                    for eline in elines.get('eline'):
                        self.append_calculated_flows(srnodes, eline.get('calculated-flows'))


        resp = self._http_get(self._get_operational_url() + REST_URL_TREEPATH)
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('treepaths') is not None:
                paths = data.get('treepaths')
                if paths.get('treepath') is not None:
                    for path in paths.get('treepath'):
                        self.append_calculated_flows(srnodes, path.get('calculated-flows'))
                        self.append_calculated_groups(srnodes, path.get('calculated-groups'))

        resp = self._http_get(self._get_operational_url() + REST_URL_ETREE)
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('etrees') is not None:
                etrees = data.get('etrees')
                if etrees.get('etree') is not None:
                    for etree in etrees.get('etree'):
                        self.append_calculated_flows(srnodes, etree.get('calculated-flows'))
                        self.append_calculated_groups(srnodes, etree.get('calculated-groups'))

        resp = self._http_get(self._get_operational_url() + REST_URL_PATH_MPLS_NODES)
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            mpls_nodes = data.get('mpls-nodes')
            if mpls_nodes is not None:
                self.append_calculated_flow_nodes(srnodes, mpls_nodes.get('calculated-flow-nodes'))

        resp = self._http_get(self._get_operational_url() + REST_URL_ELINE_MPLS_NODES)
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            mpls_nodes = data.get('eline-nodes')
            if mpls_nodes is not None:
                self.append_calculated_flow_nodes(srnodes, mpls_nodes.get('calculated-flow-nodes'))

        resp = self._http_get(self._get_operational_url() + REST_URL_ETREE_SR_NODES)
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
