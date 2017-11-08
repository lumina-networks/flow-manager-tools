"""Flow Manager Topology

This module loads the topology information such as controller, switches,
and links. It provides the basic primitives to access to topology information.

"""

class Topo(object):

    def __init__(self, props):
        # Disable warnings
        try:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except:
            pass
