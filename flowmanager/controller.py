"""Controller

This module contains the primitives to access controller information.

"""

# Define all URL values
LUMINA_FLOW_MANAGER_PREFIX = 'lumina-flowmanager-'
BROCADE_FLOW_MANAGER_PREFIX = 'brocade-bsc'

REST_URL_ELINE = 'eline:elines'
REST_URL_ELINE_STATS = 'eline:get-stats'
REST_URL_ELINE_MPLS_NODES = 'eline-mpls:eline-nodes'

REST_URL_PATH = 'path:paths'
REST_URL_PATH_MPLS_NODES = 'path-mpls:mpls-nodes'

REST_URL_ETREE = 'etree:etrees'
REST_URL_ETREE_STATS = 'etree:get-stats'
REST_URL_ETREE_SR_NODES = 'etree-sr:etree-nodes'

REST_URL_TREEPATH = 'tree-path:treepaths'

REST_CONTAINER_SR = 'sr:sr'

class Controller(object):

    def __init__(self, props, controller_vip):
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
        self.appropriated_url = self._get_appropriated_url()


    def _get_appropriated_url(self):
        URL_PREFIX = '/'
        REST_URL = URL_PREFIX + LUMINA_FLOW_MANAGER_PREFIX
        REQUEST_URL = REST_URL + 'path:paths'
        resp = self._http_get(self._get_operational_url() + REQUEST_URL)
        if resp is not None and resp.status_code == 400:
            return URL_PREFIX + BROCADE_FLOW_MANAGER_PREFIX
        else:
            return URL_PREFIX + LUMINA_FLOW_MANAGER_PREFIX

    def _create_base_url(self, required_url):
        return self.appropriated_url + required_url

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
            SR_URL = self._create_base_url(REST_CONTAINER_SR)
            brocadesr = node.get(SR_URL)
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
                        SR_URL = self._create_base_url(REST_CONTAINER_SR)
                        brocadesr = node.get(SR_URL)
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


        resp = self._http_get(self._get_operational_url() + self._create_base_url(REST_URL_ELINE))
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('elines') is not None:
                elines = data.get('elines')
                if elines.get('eline') is not None:
                    for eline in elines.get('eline'):
                        self.append_calculated_flows(srnodes, eline.get('calculated-flows'))


        resp = self._http_get(self._get_operational_url() + self._create_base_url(REST_URL_TREEPATH))
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('treepaths') is not None:
                paths = data.get('treepaths')
                if paths.get('treepath') is not None:
                    for path in paths.get('treepath'):
                        self.append_calculated_flows(srnodes, path.get('calculated-flows'))
                        self.append_calculated_groups(srnodes, path.get('calculated-groups'))

        resp = self._http_get(self._get_operational_url() + self.create_base_url(REST_URL_ETREE))
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            if data.get('etrees') is not None:
                etrees = data.get('etrees')
                if etrees.get('etree') is not None:
                    for etree in etrees.get('etree'):
                        self.append_calculated_flows(srnodes, etree.get('calculated-flows'))
                        self.append_calculated_groups(srnodes, etree.get('calculated-groups'))

        resp = self._http_get(self._get_operational_url() + self._create_base_url(REST_URL_PATH_MPLS_NODES))
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            mpls_nodes = data.get('mpls-nodes')
            if mpls_nodes is not None:
                self.append_calculated_flow_nodes(srnodes, mpls_nodes.get('calculated-flow-nodes'))

        resp = self._http_get(self._get_operational_url() + self._create_base_url(REST_URL_ELINE_MPLS_NODES))
        if resp is not None and resp.status_code == 200 and resp.content is not None:
            data = json.loads(resp.content)
            mpls_nodes = data.get('eline-nodes')
            if mpls_nodes is not None:
                self.append_calculated_flow_nodes(srnodes, mpls_nodes.get('calculated-flow-nodes'))

        resp = self._http_get(self._get_operational_url() + self._create_base_url(REST_URL_ETREE_SR_NODES))
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

    def print_etree_stats(self, filters=None):

        resp = self._http_get(self._get_config_url() + self.create_base_url(REST_URL_ETREE))
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get openflow information'
            return

        data = json.loads(resp.content)
        if 'etrees' not in data or 'etree' not in data['etrees'] or data['etrees']['etree'] is None:
            return

        for etree in data['etrees']['etree']:
            if contains_filters(filters,etree['name']):
                print 'etree: ' + etree['name']
                resp = self._http_post(self._get_operations_url()+ self.create_base_url(REST_URL_ETREE_STATS),'{"input":{"name": "'+etree['name']+'"}}')
                print json.dumps(json.loads(resp.content),indent=2)


    def print_etree_summary(self, filters=None):

        resp = self._http_get(self._get_config_url() + self.create_base_url(REST_URL_ETREE))
        if resp is None or resp.status_code != 200 or resp.content is None:
            print 'ERROR: no data found while trying to get etree information'
            return

        data = json.loads(resp.content)
        if 'etrees' not in data or 'etree' not in data['etrees'] or data['etrees']['etree'] is None:
            return

        for etree in data['etrees']['etree']:
            if contains_filters(filters,etree['name']):

                resp = self._http_post(self._get_operations_url()+ self.create_base_url(REST_URL_ETREE_STATS),'{"input":{"name": "'+etree['name']+'"}}')
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

                resp = self._http_get(self._get_config_url() + self.create_base_url(REST_URL_TREEPATH) + '/treepath/{}'.format(etree['treepath-name']))
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

    def print_sr_summary_all(self):
        srnodes = self._get_sr_nodes_paths()

        nodeslist = srnodes.keys()
        for fromindex in range(len(nodeslist) - 1):
            for toindex in range(fromindex + 1,len(nodeslist)):
                self.print_sr_summary(nodeslist[fromindex], nodeslist[toindex], srnodes)

    def print_sr_summary(self, source, destination, srnodes=None):
        if srnodes is None:
            srnodes = self._get_sr_nodes_paths()

        source = str(source)
        if not source.startswith('openflow:'):
            if 'openflow:' + source in srnodes:
                source = 'openflow:' + source
            else:
                for nodeid in srnodes:
                    srnode = srnodes.get(nodeid)
                    if srnode.get('mpls-label') and str(srnode.get('mpls-label')) == source:
                        source = nodeid
                        break
        if not source.startswith('openflow:'):
            print "ERROR: source {} not found".format(source)
            return

        destination = str(destination)
        if not destination.startswith('openflow:'):
            if 'openflow:' + destination in srnodes:
                destination = 'openflow:' + destination
            else:
                for nodeid in srnodes:
                    srnode = srnodes.get(nodeid)
                    if srnode.get('mpls-label') and str(srnode.get('mpls-label')) == destination:
                        destination = nodeid
                        break
        if not destination.startswith('openflow:'):
            print "ERROR: destination {} not found".format(destination)
            return

        if destination not in srnodes[source]['primary-paths']:
            print "ERROR: source {} cannot reach destination {}".format(source, destination)
            return

        if destination == source:
            print "ERROR: source {} and destination {} cannot be the same".format(source, destination)
            return

        print "SR packects from: {} to: {}".format(source, destination)
        sources = [{source: 1}]
        while len(sources) > 0:
            current = sources[0].keys()[0]
            tabs = sources[0][current]
            del sources[0]

            srnode = srnodes[current]['primary-paths']
            if destination not in srnode:
                print "ERROR: {} cannot reach destination {}".format(current, destination)
                continue

            srdest = srnode[destination]
            print "{} node: ({}) flow packets ({}) group packets ({})".format('\t' * tabs, current, self._get_flow_stats_packets(srnode[destination]['flow-id']), self._get_group_stats_packets(srnode[destination]['group-id']))
            hops = srnode[destination].get('next-hops')
            if not hops:
                continue
            for hop in hops:
                if hop != destination:
                    sources.insert(0, {hop: tabs + 1})

        print ""