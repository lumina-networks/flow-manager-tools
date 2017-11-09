"""Flow Manager Link

This module contains the implementation of links

"""

class Link(object):

    def __init__(self, name, expected_dst=None):
        self.name = name
        self.source = _get_link_properties(name)
        self.expected_dst_name = expected_dst
        self.expected = _get_link_properties(expected_dst) if expected_dst else {}
        self.of_dst = None
        self.of = {}
        self.sr_dst = None
        self.sr = {}

    def add_sr_dst(self, name):
        self.sr_dst = name
        self.sr = _get_link_properties(name)

    def add_of_dst(self, name):
        self.of_dst = name
        self.of = _get_link_properties(name)


    def check(self, validate_sr=True, validate_host=False):
        if not validate_host and self.source['type'] == 'host':
            return True
        if not validate_host and 'type' in self.expected and self.expected['type'] == 'host':
            return True
        if not self.expected_dst_name or not self.of_dst or self.expected_dst_name != self.of_dst or (validate_sr and (not self.sr_dst or self.expected_dst_name != self.sr_dst)):
            print "ERROR: link not in sync source '{}', {}, {}, {} ".format(self.name,
                "expected destination '{}'".format(self.expected_dst_name) if self.expected_dst_name else "unexpected link",
                "openflow destination '{}'".format(self.of_dst) if self.of_dst else "not found in openflow",
                "sr destination '{}'".format(self.sr_dst) if self.sr_dst else "not found in sr"
                )

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
