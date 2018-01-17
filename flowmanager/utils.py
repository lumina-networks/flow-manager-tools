"""

This class contains common methods to be consumed by all modules.

"""


def check_mandatory_values(obj, names):
    for name in names:
        if name not in obj or not obj[name]:
            raise Exception("{} is missing in object {}".format(name, obj))


def contains_filters(filters=None, value=None):
    if not value:
        return False
    if not filters or len(filters) <= 0:
        return True
    for fil in filters:
        if fil not in value:
            return False
    return True
