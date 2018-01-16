import logging


class Group(object):

    def __init__(self, node, node_of_name, groupid):
        self.node = node
        self.node_of_name = node_of_name
        self.groupid = groupid
        self.of_config = None
        self.of_operational = None
        self.switch = None
        self.fm = None
        self.calculated = False

    def add_of_config(self, group):
        self.of_config = group

    def add_of_operational(self, group):
        self.of_operational = group

    def add_switch(self, group):
        self.switch = group

    def add_fm(self, group):
        self.fm = group

    def mark_as_calculated(self):
        self.calculated = True

    def check(self):
        if self.of_config and not self.switch:
            print "ERROR: {}({}) group {} is not runnig in the switch. {}".format(self.node, self.node_of_name, self.groupid, self._get_info_msg())
        elif self.of_config and not self.of_operational:
            print "ERROR: {}({}) group {} not found in operational datastore. {}".format(self.node, self.node_of_name, self.groupid, self._get_info_msg())
        elif self.of_config and not self.fm:
            print "ERROR: {}({}) group {} is not being monitored. {}".format(self.node, self.node_of_name, self.groupid, self._get_info_msg())
        elif self.of_config and not self.calculated:
            print "ERROR: {}({}) group {} not found in calculated groups. {}".format(self.node, self.node_of_name, self.groupid, self._get_info_msg())
        elif not self.of_config and self.switch:
            print "ERROR: {}({}) group {} runnig in switch but not configured. {}".format(self.node, self.node_of_name, self.groupid, self._get_info_msg())
        elif not self.of_config and self.of_operational:
            print "ERROR: {}({}) group {} found operational datastore but not in configuration. {}".format(self.node, self.node_of_name, self.groupid, self._get_info_msg())
        elif not self.of_config and not self.of_operational and not self.switch and self.fm:
            print "ERROR: {}({}) group {} monitored but not running neither configured. {}".format(self.node, self.node_of_name, self.groupid, self._get_info_msg())
        elif not self.of_config and self.calculated:
            print "ERROR: {}({}) group {} calculated but not configured. {}".format(self.node, self.node_of_name, self.groupid, self._get_info_msg())
        else:
            logging.debug("GROUP: OK: %s %s", self.groupid,
                          self._get_info_msg())
            return True

    def _get_info_msg(self):
        return "{}({}) of config ({}), of operational ({}), switch ({}), monitored ({}), calculated ({})".format(self.node, self.node_of_name, self.of_config != None, self.of_operational != None, self.switch != None, self.fm != None, self.calculated)
