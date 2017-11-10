import json

cache = {}

def get_from_cache_object(ctrl, url):
    if ctrl.name in cache:
        return cache[ctrl.name].get(url)

def add_to_cache_object(ctrl, url):
    if ctrl.name in cache:
        return cache[ctrl.name].get(url)

def get_topology(ctrl, topology_name, use_cache=True):
    url = ctrl.get_operational_url() + '/network-topology:network-topology/topology/{}'.format(topology_name)
    topology = get_from_cache_object(ctrl, url) if use_cache else None
    if not use_cache or not topology:
        resp = ctrl.http_get(url)
        if resp is None or resp.status_code != 200 or resp.content is None:
            return None
        data = json.loads(resp.content)
        topology = data.get('topology')
        if topology is not None and len(topology) <= 0:
            return None
        topology = topology[0]
        add_to_cache_object(ctrl, topology)

    return topology

def get_openflow(ctrl, use_cache=True):
    url = ctrl.get_operational_url() + '/opendaylight-inventory:nodes'
    data = get_from_cache_object(ctrl, url) if use_cache else None
    if not use_cache or not data:
        resp = ctrl.http_get(url)
        if resp is None or resp.status_code != 200 or resp.content is None:
            return None
        data = json.loads(resp.content)
        add_to_cache_object(ctrl, data)

    return data

def get_topology_nodes(ctrl, topology_name, filter_hosts=True, filter_anycast=True, use_cache=True):

    topology = get_topology(ctrl, topology_name, use_cache)
    if topology is None:
        return None

    nodes = topology.get('node')
    if nodes is None or len(nodes) <= 0:
        return None

    result = []
    for node in nodes:
        if filter_hosts and unicode(node['node-id']).startswith(unicode('host:')):
            continue
        if filter_anycast and unicode(node['node-id']).startswith(unicode('anycast:')):
            continue
        result.append(node['node-id'])

    return result if len(result) > 0 else None


def get_topology_links(ctrl, topology_name, filter_hosts=True, use_cache=True):

    topology = get_topology(ctrl, topology_name, use_cache)
    if topology is None:
        return None

    links = topology.get('link')
    if links is None or len(links) <= 0:
        return None

    result = {}
    for link in links:
        if filter_hosts and link['source']['source-node'].startswith('host:'):
            continue
        if filter_hosts and link['destination']['dest-node'].startswith('host:'):
            continue
        result[link['link-id']] = link

    return result if len(result) > 0 else None


def get_openflow_connected_nodes(ctrl, use_cache=True):
    data = get_openflow(ctrl, use_cache)
    if data is None or 'nodes' not in data or 'node' not in data['nodes']:
        return None

    nodes = {}
    for node in data['nodes']['node']:
        name = node['id']
        if name.startswith('openflow'):
            continue
        nodes[name] = node

    return nodes if len(nodes) > 0 else None
