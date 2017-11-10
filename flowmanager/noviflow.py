from flowmanager.switch import Switch

class Noviflow(Switch):
    def __init__(self, props, expected=False):
        Switch.__init__(self, props, expected)
