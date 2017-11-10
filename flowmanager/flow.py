import logging

CALCULATED_EXCEPTIONS=['fm-sr-link-discovery']

def get_prefix(cookie):
    return int(cookie) >> 54


def get_version(cookie):
    return (int(cookie) & 0x00000000FF000000) >> 24


def get_id(cookie):
    return (int(cookie) & 0x00FFFFFF00000000) >> 32


class Flow(object):

    def __init__(self, node, node_of_name, cookie=None, table=None, name=None):
        self.node = node
        self.node_of_name = node_of_name
        self.of_operational = []
        self.of_config = []
        self.switch = []
        self.fm = []
        self.calculated = False

        self.cookie = cookie
        self.table = table
        self.name = name

        if table is not None and name is not None and cookie is not None:
            self.flowid = "{}({})/table/{}/name/{}/id/{}/version/{}".format(node, node_of_name, table, name, get_id(cookie), get_version(cookie))
        elif table is not None and name is not None:
            self.flowid = "{}({})/table/{}/name/{}".format(node, node_of_name, table, name)
        else:
            self.flowid = "{}({})/id/{}/version/{}".format(node, node_of_name, get_id(cookie), get_version(cookie))

    def add_of_config(self, flow):
        logging.debug("FLOW: %s mard as configured",self.flowid)
        self.of_config.append(flow)

    def add_of_operational(self, flow):
        logging.debug("FLOW: %s mard as operational",self.flowid)
        self.of_operational.append(flow)

    def add_switch(self, flow):
        logging.debug("FLOW: %s mard as running in switch",self.flowid)
        self.switch.append(flow)

    def add_fm(self, flow):
        logging.debug("FLOW: %s mard as monitored",self.flowid)
        self.fm.append(flow)

    def mark_as_calculated(self):
        logging.debug("FLOW: %s mark as calculated",self.flowid)
        self.calculated = True

    def check(self):
        config = len(self.of_config) > 0
        operational = len(self.of_config) > 0
        switch = len(self.switch) > 0
        fm = len(self.fm) > 0

        if (len(self.of_config) > 1):
            print "ERROR: flow {} duplicated in configuration. {}".format(self.flowid, self._get_info_msg())
        elif (len(self.of_operational) > 1):
            print "ERROR: flow {} duplicated in operational. {}".format(self.flowid, self._get_info_msg())
        elif (len(self.switch) > 1):
            print "ERROR: flow {} duplicated in switch. {}".format(self.flowid, self._get_info_msg())
        elif (len(self.fm) > 1):
            print "ERROR: flow {} duplicated in monitored. {}".format(self.flowid, self._get_info_msg())
        elif config and not switch:
            print "ERROR: flow {} is not runnig in the switch. {}".format(self.flowid, self._get_info_msg())
        elif config and not operational:
            print "ERROR: flow {} not found in operational datastore. {}".format(self.flowid, self._get_info_msg())
        elif config and not fm:
            print "ERROR: flow {} is not being monitored. {}".format(self.flowid, self._get_info_msg())
        elif config and not self.calculated and str(self.of_config[0]['id']) not in CALCULATED_EXCEPTIONS:
            print "ERROR: flow {} not found in calculated flows. {}".format(self.flowid, self._get_info_msg())
        elif not config and switch:
            print "ERROR: flow {} runnig in switch but not configured. {}".format(self.flowid, self._get_info_msg())
        elif not config and operational:
            print "ERROR: flow {} found operational datastore but not in configuration. {}".format(self.flowid, self._get_info_msg())
        elif not config and not operational and not switch and fm:
            print "ERROR: flow {} monitored but not running neither configured. {}".format(self.flowid, self._get_info_msg())
        elif not config and self.calculated:
            print "ERROR: flow {} calculated but not configured. {}".format(self.flowid, self._get_info_msg())
        ##TODO check version
        else:
            logging.debug("FLOW: OK: %s %s", self.flowid, self._get_info_msg())
            return True

    def _get_info_msg(self):
        msg = "{}({})".format(self.node, self.node_of_name)
        if (len(self.of_config) > 0):
            flow = self.of_config[0]
            msg = msg + ", " + "config table/{}/name/{}/id/{}/version/{}".format(flow['table_id'],flow['id'],get_id(flow['cookie']),get_version(flow['cookie']))
        if (len(self.of_operational) > 0):
            flow = self.of_operational[0]
            msg = msg + ", " + "operational table/{}/name/{}/id/{}/version/{}".format(flow['table_id'],flow['id'],get_id(flow['cookie']),get_version(flow['cookie']))
        if (len(self.switch) > 0):
            flow = self.switch[0]
            msg = msg + ", " + "switch id/{}/version/{}".format(get_id(flow['cookie']),get_version(flow['cookie']))
        if (len(self.fm) > 0):
            flow = self.fm[0]
            msg = msg + ", " + "monitored name/{}".format(flow['id'])

        return msg
