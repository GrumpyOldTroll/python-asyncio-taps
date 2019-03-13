import PyTAPS as taps
import asyncio
import sys
color = "yellow"


class TestClient():
    def __init__(self):
        self.connection = None
        self.preconnection = None
        # Get event loop
        self.loop = asyncio.get_event_loop()

    def handle_sent(self, message_ref):
        taps.print_time("Sent cb received, message " + str(message_ref) +
                        " has been sent.", color)
        self.connection.close()
        taps.print_time("Queued closure of connection.", color)

    def handle_send_error(self):
        taps.print_time("SeSendError cb received.", color)
        print("Error sending message")

    def handle_initiate_error(self):
        taps.print_time("InitiateError cb received.", color)
        print("Error init")
        self.loop.stop()

    def handle_closed(self):
        taps.print_time("Connection closed, stopping event loop.", color)
        self.loop.stop()

    def handle_ready(self):
        taps.print_time("Ready cb received.", color)
        self.connection.on_sent(self.handle_sent)
        self.connection.on_send_error(self.handle_send_error)
        self.connection.on_closed(self.handle_closed)
        taps.print_time("Connection cbs set.", color)
        msgref = self.connection.send_message("Hello\n")
        taps.print_time("send_message called.", color)

    async def main(self):
        # Create endpoint objects
        ep = taps.RemoteEndpoint()
        lp = None
        taps.print_time("Created endpoint objects.", color)
        # See if a remote and/or local address/port has been specified
        if len(sys.argv) >= 3:
            ep.with_address(str(sys.argv[1]))
            ep.with_port(int(sys.argv[2]))
            if len(sys.argv) >= 4:
                lp = taps.LocalEndpoint()
                lp.with_interface(str(sys.argv[3]))
                if len(sys.argv) == 5:
                    lp.with_port(int(sys.argv[4]))
                elif len(sys.argv) > 5:
                    exit("Please call with remoteAddress, remotePort, "
                         "(optional) localAddress, (optional) localPort")
        else:
            exit("Please call with remoteAddress, remotePort, "
                 "(optional) localAddress, (optional) localPort")
        # Create transportProperties Object and set properties
        # tp = taps.transportProperties()
        # tp.add("Reliable_Data_Transfer", taps.preferenceLevel.REQUIRE)
        # taps.print_time("Created transportProperties object.", color)
        # Create the preconnection object with the two prev created EPs
        self.preconnection = taps.Preconnection(remote_endpoint=ep,
                                                local_endpoint=lp)
        self.preconnection.on_initiate_error(self.handle_initiate_error)
        self.preconnection.on_ready(self.handle_ready)
        taps.print_time("Created preconnection object and set cbs.", color)
        # Initiate the connection
        self.connection = self.preconnection.initiate()
        taps.print_time("Called initiate, connection object created.", color)
if __name__ == "__main__":
    client = TestClient()
    client.loop.create_task(client.main())
    client.loop.run_forever()