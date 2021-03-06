

class LocalEndpoint:
    """ A local (TAPS) Endpoint with an interface
        (address for now) and port number.
    """
    def __init__(self):
        self.interface = None
        self.port = None
        self.address = None
        self.join_type = None

    def with_interface(self, interface):
        self.interface = interface

    def with_address(self, address):
        self.address = address

    def with_port(self, portNumber):
        self.port = portNumber

    def with_join(self, join_type):
        self.join_type = join_type


class RemoteEndpoint:
    """ A remote (TAPS) Endpoint with an address,
        that can either be given directly
        as an IPv4 or IPv6 or that can be given
        as a name that will be resolved with DNS.
    """
    def __init__(self):
        self.address = None
        self.port = None
        self.host_name = None

    def with_address(self, address):
        self.address = address

    def with_hostname(self, name):
        self.host_name = name

    def with_port(self, portNumber):
        self.port = portNumber
