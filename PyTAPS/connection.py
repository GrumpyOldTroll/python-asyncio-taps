import asyncio
from .endpoint import LocalEndpoint, RemoteEndpoint
from .transportProperties import TransportProperties
from .utility import *
color = "green"


class Connection:
    """The TAPS connection class.

    Attributes:
        localEndpoint (:obj:'localEndpoint', optional): LocalEndpoint of the
                       preconnection, required if the connection
                       will be used to listen
        remoteEndpoint (:obj:'remoteEndpoint', optional): RemoteEndpoint of the
                        preconnection, required if a connection
                        will be initiated
        transportProperties (:obj:'transportProperties', optional): object with
                             the transport properties
                             with specified preferenceLevel
        securityParams (tbd): Security Parameters for the preconnection
    """
    def __init__(self, local_endpoint=None, remote_endpoint=None,
                 transport_properties=None, security_parameters=None):
                # Assertions
                if local_endpoint is None and remote_endpoint is None:
                    raise Exception("At least one endpoint need "
                                    "to be specified")
                # Initializations
                self.local_endpoint = local_endpoint
                self.remote_endpoint = remote_endpoint
                self.transport_properties = transport_properties
                self.security_parameters = security_parameters
                self.loop = asyncio.get_event_loop()
                self.message_count = 0
                self.ready = None
                self.initiate_error = None
                self.sent = None
                self.send_error = None
                self.expired = None
                self.received = None
                self.received_partial = None
                self.receive_error = None
                self.closed = None
                self.reader = None
                self.writer = None
    """ Tries to create a (TCP) connection to a remote endpoint
        If a local endpoint was specified on connection class creation,
        it will be used.
    """
    async def connect(self):
        try:
                if(self.local_endpoint is None):
                    print_time("Connecting with unspecified localEP.", color)
                    self.reader, self.writer = await asyncio.open_connection(
                                        self.remote_endpoint.address,
                                        self.remote_endpoint.port)
                else:
                    print_time("Connecting with specified localEP.", color)
                    self.reader, self.writer = await asyncio.open_connection(
                                    self.remote_endpoint.address,
                                    self.remote_endpoint.port,
                                    local_addr=(self.local_endpoint.interface,
                                                self.local_endpoint.port))
        except:
            if self.initiate_error:
                print_time("Initiate Error occured.", color)
                self.loop.call_soon(self.initiate_error)
                print_time("Queued InitiateError cb.", color)
            return
        if self.ready:
            print_time("Connected successfully.", color)
            self.loop.call_soon(self.ready)
            print_time("Queued Ready cb.", color)
        return

    """ Tries to send the (string) stored in data
    """
    async def send_data(self, data, message_count):
        print_time("Writing data.", color)
        try:
            self.writer.write(data.encode())
            await self.writer.drain()
        except:
            if self.send_error:
                print_time("SendError occured.", color)
                self.loop.call_soon(self.send_error, message_count)
                print_time("Queued SendError cb.", color)
            return
        print_time("Data written successfully.", color)
        if self.sent:
            self.loop.call_soon(self.sent, message_count)
            print_time("Queued Sent cb..", color)
        return

    """ Wrapper function that assigns MsgRef
        and then calls async helper function
        to send a message
    """
    def send_message(self, data):
        print_time("Sending data.", color)
        self.message_count += 1
        self.loop.create_task(self.send_data(data, self.message_count))
        print_time("Returning MsgRef.", color)
        return self.message_count

    """ Queues reception of a message
    """
    async def receive_message(self, min_incomplete_length,
                              max_length):
        try:
            data = await self.reader.read(max_length)
        except:
            print_time("Reception Error", color)
            if self.receive_error:
                self.loop.call_soon(self.receive_error)
            return
        if self.reader.at_eof():
            print_time("Received full message", color)
            if self.received:
                self.loop.call_soon(self.received, data, "Context")
                print_time("Called received cb.", color)
            return

        elif len(data) > min_incomplete_length:
            print_time("Received partial message.", color)
            if self.received_partial:
                self.loop.call_soon(self.received_partial, data, "Context",
                                    False)
                print_time("Called partial_receive cb.", color)
    """ Wrapper function to make receive return immediately
    """
    def receive(self, min_incomplete_length=float("inf"), max_length=-1):
        self.loop.create_task(self.receive_message(min_incomplete_length,
                              max_length))
    """ Tries to close the connection
        TODO: Check why port isnt always freed
    """
    async def close_connection(self):
        print_time("Closing connection.", color)
        self.writer.close()
        await self.writer.wait_closed()
        print_time("Connection closed.", color)
        if self.closed:
            self.loop.call_soon(self.closed)

    """ Wrapper function for close_connection,
        required to make close return immediately
    """
    def close(self):
        self.loop.create_task(self.close_connection())
    """ Function to set reader/writer for passive open
    """
    def set_reader_writer(self, reader, writer):
        self.reader = reader
        self.writer = writer

    # Events for active open
    def on_ready(self, a):
        self.ready = a

    def on_initiate_error(self, a):
        self.initiate_error = a

    # Events for sending messages
    def on_sent(self, a):
        self.sent = a

    def on_send_error(self, a):
        self.send_error = a

    def on_expired(self, a):
        self.expired = a

    # Events for receiving messages
    def on_received(self, a):
        self.received = a

    def on_received_partial(self, a):
        self.received_partial = a

    def on_receive_error(self, a):
        self.receive_error = a

    # Events for closing a connection
    def on_closed(self, a):
        self.closed = a
