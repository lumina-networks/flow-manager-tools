"""

This class contains common methods to be consumed by all modules.

"""



def check_mandatory_values(obj, names):
    for name in names:
        if name not in obj or not obj[name]:
            raise Exception("{} is missing in object {}".format(name, obj))
