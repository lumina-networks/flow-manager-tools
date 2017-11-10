"""Flow Manager Link

This module contains the implementation of links

"""

import logging

class Link(object):

    def __init__(self, name, expected_dst=None):
        logging.debug('LINK: creating link %s, expected destination %s', name, expected_dst)
        self.name = unicode(name)
        self.source = _get_link_properties(name)
        self.expected_dst_name = expected_dst
        self.expected = _get_link_properties(expected_dst) if expected_dst else {}
        self.of_dst = None
        self.of = {}
        self.sr_dst = None
        self.sr = {}

    def add_sr_dst(self, link):
        logging.debug('LINK: adding segment routing link from %s to %s, expected destination %s', self.name, link, self.expected_dst_name)
        self.sr_dst = link
        self.sr = _get_link_properties(link)

    def add_of_dst(self, link):
        logging.debug('LINK: adding openflow link from %s to %s, expected destination %s', self.name, link, self.expected_dst_name)
        self.of_dst = link
        self.of = _get_link_properties(link)


    def check(self, should_be_up=True, validate_sr=True, validate_host=False):
        logging.debug('LINK: checking link source %s, expected %s, of %s, sr %s', self.name, self.expected_dst_name, self.of_dst, self.sr_dst)
        if not validate_host and self.source['type'] == 'host':
            return True
        if not validate_host and 'type' in self.expected and self.expected['type'] == 'host':
            return True
        if (not self.expected_dst_name):
            print "ERROR: unexpected link detected. Source: '{}'. Destination: openflow '{}', sr '{}'".format(self.name, self.of_dst, self.sr_dst)
        elif (not should_be_up and self.of_dst):
            print "ERROR: link should be down. Source '{}'. Destination: expected '{}', openflow '{}', sr '{}'".format(self.name, self.expected_dst_name, self.of_dst, self.sr_dst)
        elif (should_be_up and self.of_dst != self.expected_dst_name):
            print "ERROR: wrong destination. Source '{}'. Destination: expected '{}', openflow '{}', sr '{}'".format(self.name, self.expected_dst_name, self.of_dst, self.sr_dst)
        elif (validate_sr and not should_be_up and self.sr_dst):
            print "ERROR: link should be down. Source '{}'. Destination: expected '{}', openflow '{}', sr '{}'".format(self.name, self.expected_dst_name, self.of_dst, self.sr_dst)
        elif (validate_sr and should_be_up and self.sr_dst != self.expected_dst_name):
            print "ERROR: wrong destination. Source '{}'. Destination: expected '{}', openflow '{}', sr '{}'".format(self.name, self.expected_dst_name, self.of_dst, self.sr_dst)
        else:
            return True

def _get_link_properties(name):
    elements = name.split(':')
    if len(elements) > 3 or len(elements) < 2:
        raise Exception("wrong link {} format ".format(name))

    return {
        'name': name,
        'type' : elements[0],
        'id' : elements[1],
        'port': elements[2] if len(elements) >= 3 else None
    }
