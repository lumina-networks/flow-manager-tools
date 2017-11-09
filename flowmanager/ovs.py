class OVS(Switch):
    def __init__(self, props):
        Switch.__init__(self, props)

        # if IP address and user is not given
        # then we need to assume OVS is running locally
        self.execute_local = not props.get('ip') and not props.get('user')
