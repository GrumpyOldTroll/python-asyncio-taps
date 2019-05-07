import asyncio
import ssl
import ipaddress
from .yang_validate import validate, convert, YangException, YANG_FMT_XML, YANG_FMT_JSON
import xml.etree.ElementTree as ET
from .connection import Connection, DatagramHandler
from .securityParameters import SecurityParameters
from .transportProperties import *
from .endpoint import LocalEndpoint, RemoteEndpoint
from .utility import *
color = "red"


class Preconnection:
    """The TAPS preconnection class.

    Attributes:
        localEndpoint (:obj:'localEndpoint', optional):
                        LocalEndpoint of the
                        preconnection, required if the connection
                        will be used to listen
        remoteEndpoint (:obj:'remoteEndpoint', optional):
                        RemoteEndpoint of the
                        preconnection, required if a connection
                        will be initiated
        transportProperties (:obj:'transportProperties', optional):
                        Object of the transport properties
                        with specified preferenceLevels
        securityParams (:obj:'securityParameters', optional):
                        Security Parameters for the preconnection
        eventLoop (:obj: 'eventLoop', optional):
                        Event loop on which all coroutines and callbacks
                        will be scheduled, if none if given the
                        one of the current thread is used by default
    """
    def __init__(self, local_endpoint=None, remote_endpoint=None,
                 transport_properties=TransportProperties(),
                 security_parameters=None,
                 event_loop=asyncio.get_event_loop()):
                # Assertions
                if local_endpoint is None and remote_endpoint is None:
                    raise Exception("At least one endpoint needs "
                                    "to be specified")
                # Initializations from arguments
                self.local_endpoint = local_endpoint
                self.remote_endpoint = remote_endpoint
                self.transport_properties = transport_properties
                self.security_parameters = security_parameters
                self.security_context = None
                self.multicast_type = None
                self.loop = event_loop

                # Callbacks of the appliction
                self.read = None
                self.initiate_error = None
                self.connection_received = None
                self.listen_error = None
                self.stopped = None
                self.ready = None
                self.initiate_error = None
                self.connection_received = None
                self.listen_error = None
                self.stopped = None
                self.active = False

                # Security Context for SSL
                self.security_context = None
                # Connection object that will be returned on initiate
                self.connection = None
                # Which transport protocol will eventually be used
                self.protocol = None
                # Waiter required to get the correct connection object
                self.waiter = None
                # Framer object
                self.framer = None

    def from_yang(frmat, text):
        if frmat == YANG_FMT_XML:
            validate(frmat, text)
            xml_text = text
        else:
            xml_text = convert(frmat, text, YANG_FMT_XML)

        root = ET.fromstring(xml_text)
        ns = {'taps':'urn:ietf:params:xml:ns:yang:ietf-taps-api'}

        # jake 2019-05-02: *sigh* thanks for all the hate, xml...
        if root.tag != '{urn:ietf:params:xml:ns:yang:ietf-taps-api}preconnection':
            print_time("warning: unexpected root of instance: %s (instead of ietf-taps-api:preconnection" % (root.tag))
        precon = root

        # TBD: jake 2019-05-02: this api accepts only one endpoint, but the spec
        # talks about accepting multiple endpoints.  not clear what to do?  yang
        # and implementation api ideally would match tho...
        # current behavior is to just take the first and stop.

        lp = None
        for node in precon.findall('taps:local-endpoints', namespaces=ns):
            if not lp:
                lp = LocalEndpoint()
            # TBD: jake 2019-05-02: mapping from ifref to interface name?
            interface_ref = node.findtext('taps:ifref', namespaces=ns)
            local_address = node.findtext('taps:local-address', namespaces=ns)
            local_port = node.findtext('taps:local-port', namespaces=ns)
            join_type = node.findtext('taps:multicast-subscription', namespaces=ns)
            if interface_ref:
                lp.with_interface(interface_ref)
            if local_address:
                lp.with_address(local_address)
            if local_port:
                lp.with_port(local_port)
            if join_type:
                lp.with_join(join_type)
            break

        rp = None
        for node in precon.findall('taps:remote-endpoints', namespaces=ns):
            if not rp:
                rp = RemoteEndpoint()
            remote_host = node.findtext('taps:remote-host', namespaces=ns)
            remote_port = node.findtext('taps:remote-port', namespaces=ns)
            if remote_host:
                rp.with_hostname(remote_host)
            if remote_port:
                rp.with_port(remote_port)
            break

        sp = None
        security = precon.find('taps:security', namespaces=ns)
        if security:
            sp = SecurityParameters()
            for cred in security.findall('taps:credentials', namespaces=ns):
                trust_ca = cred.findtext('taps:trust-ca', namespaces=ns)
                local_identity = cred.findtext('taps:identity', namespaces=ns)
                if trust_ca:
                    sp.addTrustCA(trust_ca)
                if local_identity:
                    sp.addIdentity(local_identity)

        tp = TransportProperties()
        fn_mapping = {
            'ignore': TransportProperties.ignore,
            'prohibit': TransportProperties.prohibit,
            'require': TransportProperties.require,
            'prefer': TransportProperties.prefer,
            'avoid': TransportProperties.avoid,
        }
        for node in precon.findall('taps:transport-properties', namespaces=ns):
            prop_name = node.findtext('taps:type', namespaces=ns)
            pref = node.findtext('taps:preference', namespaces=ns)
            fn = fn_mapping.get(pref)
            if not fn:
                raise Exception('unknown transport preference: %s' % pref)
            fn(tp, prop_name)

        return Preconnection(remote_endpoint=rp,
                local_endpoint=lp,
                transport_properties=tp,
                security_parameters=sp)

    def from_yangfile(fname):
        with open(fname) as infile:
            text = infile.read()

        if fname.endswith('.xml'):
            return Preconnection.from_yang(YANG_FMT_XML, text)
        elif fname.endswith('.json'):
            return Preconnection.from_yang(YANG_FMT_JSON, text)
        else:
            try:
                check = Preconnection.from_yang(YANG_FMT_JSON, text)
                return check
            except YangException as ye:
                return Preconnection.from_yang(YANG_FMT_XML, text)

    """ Waits until it receives signal from new connection object
        to indicate it has been correctly initialized. Required because
        initiate returns the connection object.
    """
    async def await_connection(self):
        if self.waiter is not None:
            return
        self.waiter = self.loop.create_future()
        try:
            await self.waiter
        finally:
            self.waiter = None

    """ Initiates the preconnection, i.e. chooses candidate protocol,
        initializes security parameters if an encrypted conenction
        was requested, resolves address and finally calls relevant
        connection call.
    """
    async def initiate(self):
        print_time("Initiating connection.", color)
        # This is an active connection attempt
        self.active = True

        # Create set of candidate protocols
        candidate_set = self.create_candidates()

        # If the candidate set is empty issue an InitiateError cb
        if not candidate_set:
            print_time("Protocol selection Error occured.", color)
            if self.initiate_error:
                self.loop.create_task(self.initiate_error())
            return

        # If security_parameters were given, initialize ssl context
        if self.security_parameters:
            self.security_context = ssl.create_default_context(
                                                ssl.Purpose.CLIENT_AUTH)
            if self.security_parameters.identity:
                print_time("Identity: " +
                           str(self.security_parameters.identity))
                self.security_context.load_cert_chain(
                                        self.security_parameters.identity)
            for cert in self.security_parameters.trustedCA:
                self.security_context.load_verify_locations(cert)

        # Resolve address
        remote_info = await self.loop.getaddrinfo(
            self.remote_endpoint.host_name, self.remote_endpoint.port)
        self.remote_endpoint.address = remote_info[0][4][0]

        # Decide which protocol was choosen and try to connect
        if candidate_set[0][0] == 'udp':
            self.protocol = 'udp'
            print_time("Creating UDP connect task.", color)
            asyncio.create_task(self.loop.create_datagram_endpoint(
                                lambda: Connection(self),
                                remote_addr=(self.remote_endpoint.address,
                                             self.remote_endpoint.port)))
        elif candidate_set[0][0] == 'tcp':
            self.protocol = 'tcp'
            print_time("Creating TCP connect task.", color)
            asyncio.create_task(self.loop.create_connection(
                                lambda: Connection(self),
                                self.remote_endpoint.address,
                                self.remote_endpoint.port,
                                ssl=self.security_context))

        # Wait until the correct connection object has been set
        await self.await_connection()
        print_time("Returning connection object.", color)
        return self.connection
    """ Tries to start a listener, first chooses candidate protcol and
        then tries to establish it with the appropriate asyncio function
    """
    async def start_listener(self):
        print_time("Starting listener.", color)

        # Create set of candidate protocols
        candidate_set = self.create_candidates()

        # If the candidate set is empty issue an InitiateError cb
        if not candidate_set:
            print_time("Protocol selection Error occured.", color)
            if self.initiate_error:
                self.loop.create_task(self.initiate_error())
            return

        # If security_parameters were given, initialize ssl context
        if self.security_parameters:
            self.security_context = ssl.create_default_context(
                                                ssl.Purpose.CLIENT_AUTH)
            if self.security_parameters.identity:
                print_time("Identity: " +
                           str(self.security_parameters.identity))
                self.security_context.load_cert_chain(
                                        self.security_parameters.identity)
            for cert in self.security_parameters.trustedCA:
                self.security_context.load_verify_locations(cert)
        # Attempt to set up the appropriate listener for the candidate protocol
        try:
            if candidate_set[0][0] == 'udp':
                self.protocol = 'udp'
                # jake 2019-05-04: force multicast to listen on INADDR_ANY as workaround
                if self.local_endpoint.join_type:
                    loc_addr = ipaddress.ip_address(self.local_endpoint.address)
                    if loc_addr.version == 4:
                        any_addr = '0.0.0.0'
                    else:
                        any_addr = '::'
                    local_addr=(any_addr,
                                self.local_endpoint.port)
                    reuse = True
                else:
                    reuse = None
                    local_addr=(self.local_endpoint.address,
                                self.local_endpoint.port)
                # multicast listener has to resolve remote address if present and
                # ssm - jake 2019-05-02
                if self.local_endpoint.join_type == "source-specific":
                    # Resolve address
                    remote_info = await self.loop.getaddrinfo(
                        self.remote_endpoint.host_name, self.remote_endpoint.port)
                    self.remote_endpoint.address = remote_info[0][4][0]

                print_time('listening udp on %s' % (local_addr,))
                await self.loop.create_datagram_endpoint(
                                lambda: DatagramHandler(self),
                                local_addr=local_addr, reuse_port=reuse)
            elif candidate_set[0][0] == 'tcp':
                self.protocol = 'tcp'
                server = await self.loop.create_server(
                                lambda: Connection(self),
                                self.local_endpoint.interface,
                                self.local_endpoint.port,
                                ssl=self.security_context)
        except Exception as ex:
            print_time("Listen Error occured.: %s" % (ex), color)
            if self.listen_error:
                self.loop.create_task(self.listen_error())

        print_time("Starting " + self.protocol + " Listener on " +
                   (str(self.local_endpoint.address) if
                    self.local_endpoint.address else "default") + ":" +
                   str(self.local_endpoint.port), color)
        return

    """ Wrapper function for start_listener task
    """
    async def listen(self):
        # This is a passive connection
        self.active = False

        # Create start_listener task so we can return right away
        self.loop.create_task(self.start_listener())
        return

    """ Decides which protocols are candidates and then orders them
        according to the TAPS interface draft
    """
    def create_candidates(self):
        # Get the protocols know to the implementation from transportProperties
        available_protocols = get_protocols()

        # At the beginning, all protocols are candidates
        candidate_protocols = dict([(row["name"], list((0, 0)))
                                   for row in available_protocols])

        # Iterate over all available protocols and over all properties
        for protocol in available_protocols:
            for transport_property in self.transport_properties.properties:
                match = protocol.get(transport_property, False)
                protName = protocol["name"]
                if protName == transport_property:
                    # jake 2019-05-02: protocol name as auto-property? or should
                    # these be added to the set of properties?
                    # also: is default-false reasonable and not everything has to
                    # be in every protocol profile?
                    match = True
                preference = self.transport_properties.properties[transport_property]
                # If a protocol has a prohibited property remove it
                if preference is PreferenceLevel.PROHIBIT:
                    if match is True and protName in candidate_protocols:
                        print_time('removing %s (prohibited on %s)' % (protName, transport_property))
                        del candidate_protocols[protName]
                # If a protocol doesnt have a required property remove it
                if preference is PreferenceLevel.REQUIRE:
                    if match is False and protName in candidate_protocols:
                        print_time('removing %s (on required %s)' % (protName, transport_property))
                        del candidate_protocols[protName]
                # Count how many PREFER properties each protocol has
                if preference is PreferenceLevel.PREFER:
                    if match is True and protName in candidate_protocols:
                        print_time('liking %s (on preferred %s)' % (protName, transport_property))
                        candidate_protocols[protName][0] += 1
                # Count how many AVOID properties each protocol has
                if preference is PreferenceLevel.AVOID:
                    if match is True and protName in candidate_protocols:
                        print_time('disliking %s (on avoided %s)' % (protName, transport_property))
                        candidate_protocols[protName][1] -= 1

        # Sort candidates by number of PREFERs and then by AVOIDs on ties
        sorted_candidates = sorted(candidate_protocols.items(),
                                   key=lambda value: (value[1][0],
                                   value[1][1]), reverse=True)

        return sorted_candidates

    async def resolve(self):
        # Resolve address
        remote_info = await self.loop.getaddrinfo(
            self.remote_endpoint.host_name, self.remote_endpoint.port)
        self.remote_endpoint.address = remote_info[0][4][0]

    # Set the framer
    def frame_with(self, a):
        self.framer = a

    # Events for active open
    def on_ready(self, a):
        self.ready = a

    def on_initiate_error(self, a):
        self.initiate_error = a

    # Events for passive open
    def on_connection_received(self, a):
        self.connection_received = a

    def on_listen_error(self, a):
        self.listen_error = a

    def on_stopped(self, a):
        self.stopped = a
