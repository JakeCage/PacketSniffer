'''

Packet sniffer module

Intercepts and decodes packets using winpcapy

Last modified 10/22/2015


'''




import socket
import string
import threading

try:
    from winpcapy import *
    from winpcapy_ex import *
except OSError:
    raise OSError("pcap driver not found! \nInstall it from winpcap.org")


# The PacketSniffer class is the main object for capturing packets
#
# example:
#
#	sniffer = PacketSniffer()
#	adapters = sniffer.adapters
#	sniffer.listenAdapter( adapters[0]["name"] )
#	sniffer.start()


class PacketSniffer:		

    def __init__(self):
        # Set up the default packet handler so winpcap can use it
        # In this case use CFUNCTYPE to match the types of the C function
        # u_char *param is a dummy variable, as reported by the winpcap documentation

        ##void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
        PHAND = CFUNCTYPE(None, POINTER(c_ubyte), POINTER(pcap_pkthdr), POINTER(c_ubyte))
        self._CFUNCpacketHandlerDefault = PHAND(self._packetHandlerDefault)

        # Prevent AttributeErrors, set these for later
        self._handle     = None
        self._thread     = None
        self._doNotLoop  = False
        self.onPacket    = None
        self.isCapturing = False
        self.bypassDefaultPacketHandling = False

        # This MUST be called to capture packets, might as well set it now
        self.adapters = self._getAdapterInfo()

        return


    # Method to parse packet data and relay it to a user-specified function
    # never needs to be called, pretend it's private
    def _packetHandlerDefault(self, param, header, pkt_data):

        # Break apart the header by first decoding the IPv4 header and then using the protocol field
        # to decode the protocol-specific header
        #
        # To extract numbers from an odd number of bits, we employ bitwise AND statements
        # and bitwise shifts.
        #
        # Example: pkt_data[14] = [ version (4 bit) ][ IHL (4 bit) ]
        # Therefore
        # 	version = pkt_data[14] >> 4
        #	ihl     = pkt_data[14] & 15 (00001111)

        # Yes I wrote all this myself

        ##print("Processing packet")

        # If the capturing is set to stop, end everything and close
        if self._doNotLoop == True:
            ##print("Termination flag noticed")
            self.isCapturing = False
            pcap_breakloop(self._handle)
            pcap_close(self._handle)
            self._thread = None
            return

        # If there's no callback, don't bother
        if not self.onPacket:
            return

        # If the flag to ignore the default packet handler is set, pass raw arguments to the user handler
        if self.bypassDefaultPacketHandling:
            self.onPacket(self, param, header, pkt_data)
            return

        # Note that the "header" param doesn't actually contain the packet header
        # No idea why it's named that


        # Begin by decoding the Internet layer header

        # Grab version, IPv4 VS IPv6
        # The first 14 bytes of the packet can be discarded, they are the link layer headers
        version = pkt_data[14] >> 4

        # If we are unable to find where the payload begins, treat the entire packet as payload
        payloadStart = 14

        if version == 4:
            # IPv4 header structure
            # https://en.wikipedia.org/wiki/IPv4#Packet_structure
            data = {
                'length'         :  header.contents.len,       # Length of header + payload + 14
                'timestamp'      :  header.contents.ts.tv_sec, # Unix timestamp

                'ethernetPrefix' :  pkt_data[0:14],

                'version'        :  pkt_data[14] >> 4,
                'ihl'            :  pkt_data[14] & 15,
                'dscp'           :  pkt_data[15] >> 2,
                'ecn'            :  pkt_data[15] &  3,
                'totalLength'    : (pkt_data[16] << 8) + pkt_data[17],
                'identification' : (pkt_data[18] << 8) + pkt_data[19],
                'flags'          :  pkt_data[20] >> 5,
                'fragmentOffset' :((pkt_data[20] & 31) << 8) + pkt_data[21],
                'ttl'            :  pkt_data[22],
                'protocol'       :  pkt_data[23],
                'headerChecksum' : (pkt_data[24] << 8) + pkt_data[25],
                'sourceAddr'     :  pkt_data[26:30],
                'destinationAddr':  pkt_data[30:34],
            }

            if data["ihl"] > 5:
                data["options"] = pkt_data[34:38]

            # Byte where the payload starts
            payloadStart = 14 + (data["ihl"] * 4)

            # The protocol number
            protocol     = data["protocol"]


        elif version == 6:
            # IPv6 header structure
            # https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
            data = {
                'length'         :  header.contents.len,
                'timestamp'      :  header.contents.ts.tv_sec,

                'ethernetPrefix' :  pkt_data[0:14],

                'version'        :  pkt_data[14] >> 4,
                'trafficClass'   : (pkt_data[14] << 4) + pkt_data[15] >> 4,
                'flowLabel'      :((pkt_data[15] & 15) << 16) + (pkt_data[16] << 8) + pkt_data[17],
                'payloadLength'  : (pkt_data[18] << 8) + pkt_data[19],
                'nextHeader'     :  pkt_data[20],
                'hopLimit'       :  pkt_data[21],
                'sourceAddr'     :  pkt_data[22:38],
                'destinationAddr':  pkt_data[38:54]
            }

            # Byte where the payload starts
            payloadStart = 54 # IPv6 is always 40 bytes, + the 14 bytes of the ethernet header

            # The protocol number
            protocol     = data["nextHeader"]

        else:
            # Packet is neither IPv4 nor IPv6, don't process it
            return


        # Use the Internet header to grab the Internet data
        pkt_cont = pkt_data[ payloadStart : data["length"] ]


        # Now we must decode the transport layer headers
        # During the Internet layer header decoding we took the protocol, which is a number
        # that represents the transport layer's header structure. Below, we decode protocol 6 (TCP)
        # and protocol 17 (UDP). For the full list see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        # TCP header
        # structure here https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
        if protocol == 6: # TCP

            # TCP header information
            data["tcp"] = {
                "sourcePort"           :(pkt_cont[0]  << 8 ) +  pkt_cont[1],
                "destinationPort"      :(pkt_cont[2]  << 8 ) +  pkt_cont[3],
                "sequenceNumber"       :(pkt_cont[4]  << 24) + (pkt_cont[5] << 16) + (pkt_cont[6]  << 8) + pkt_cont[7],
                "acknowledgementNumber":(pkt_cont[8]  << 24) + (pkt_cont[9] << 16) + (pkt_cont[10] << 8) + pkt_cont[11],
                "dataOffset"           : pkt_cont[12] >> 4,
                "reserved"             :(pkt_cont[12] & 13) >> 1,

                # Flags
                "NS"  : pkt_cont[12] & 1,
                "CWR" : pkt_cont[13] & 128,
                "ECE" : pkt_cont[13] & 64,
                "URG" : pkt_cont[13] & 32,
                "ACK" : pkt_cont[13] & 16,
                "PSH" : pkt_cont[13] & 8,
                "RST" : pkt_cont[13] & 4,
                "SYN" : pkt_cont[13] & 2,
                "FIN" : pkt_cont[13] & 1,

                # Continued information
                "windowSize"    :(pkt_cont[14] << 8) + pkt_cont[15],
                "checksum"      :(pkt_cont[16] << 8) + pkt_cont[17],
                "urgentPointer" :(pkt_cont[18] << 8) + pkt_cont[19],
                "options"       : pkt_cont[20:24]
            }

            # The payload bytes as determined by the dataOffset and IHL fields
            # Each is a 4-bit field counting the number of 32-bit words in the entire header
            # Therefore, (IHL * 4) + (dataOffset * 4) = first payload byte
            data["rawPayload"] = pkt_cont[data["tcp"]["dataOffset"] * 4 : data["length"] ]




        # UDP header
        # structure here https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
        if protocol == 17: # UDP

            data["udp"] = {
                # Bit boring really
                "sourcePort"      :(pkt_cont[0] << 8) + pkt_cont[1],
                "destinationPort" :(pkt_cont[2] << 8) + pkt_cont[3],
                "length"          :(pkt_cont[4] << 8) + pkt_cont[5],
                "checksum"        :(pkt_cont[6] << 8) + pkt_cont[7],
            }

            # Also boring, the header's always 8 bytes
            data["rawPayload"] = pkt_cont[ 8 : data["length"] ]




        # Done with headers!


        dPayload = ""
        try:
            # Decode the payload, removing non-printable bytes
            for byte in data["rawPayload"]:
                char = chr(byte)
                if char in string.printable:
                    dPayload = dPayload + char
                else:
                    dPayload = dPayload + "."

        except KeyError:

            # Structured so you could easily add more protocol handling above.
            # data["rawPayload"] is only defined if the protocol was handled.
            # For more protocols and their header structures see:
            # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

            dPayload = "Protocol not implemented: {0}".format(protocol)

        # Add the decoded payload to our data
        data["decodedPayload"] = dPayload

        # Finally, relay this packet to the callback
        # pass self to allow the callback function to access data in the sniffer object
        self.onPacket(self, data)



    # getAdapterInfo returns a list of adapters and their descriptions
    # This is stored in object.adapter, no need to call this function

    def _getAdapterInfo(self):
        # Collect adapters, specify error buffer size to default
        alldevs = POINTER(pcap_if_t)()
        errbuf  = create_string_buffer(PCAP_ERRBUF_SIZE)

        # Handle non-zero exit code from C function during adapter query
        if pcap_findalldevs(byref(alldevs), errbuf) == -1:
            # Before we exit, free the adapter list!
            # This needs to be called before any return or exception statement in this method
            pcap_freealldevs(alldevs)
            raise pcapError("Error in pcap_findalldevs:", errbuf.value)

        # Get information handle from pcap
        try:
            devNamePointer = alldevs.contents
        except:
            pcap_freealldevs(alldevs)
            raise pcapError("Error in pcap_findalldevs: Need administrator privilege or pcap not properly installed")


        # Iterate over the adapters we get, collect their names and descriptions
        adapters = []

        while devNamePointer:

            # Gather addresses for each network adapter
            ip4 = None
            ip6 = None

            addressPointer = devNamePointer.addresses.contents

            # Iterate over the addresses we get, grabbing their readable forms
            while addressPointer:
                # IPv4
                if addressPointer.addr.contents.sa_family == socket.AF_INET:
                    # Cast sockaddr -> sockaddr_in and convert to readable address
                    ipcast = cast(addressPointer.addr,POINTER(sockaddr_in))
                    ip4    = iptos(ipcast.contents.sin_addr.S_un.S_un_b)

                # IPv6
                elif addressPointer.addr.contents.sa_family == socket.AF_INET6:
                    # Same as above for IPv6
                    ipcast = cast(addressPointer.addr,POINTER(sockaddr_in6))
                    ip6    = ip6tos(ipcast)
                    ip6    = ip6.split("%", 1)[0] # Remove scope ID from IPv6 address

                # Select the next address, break otherwise
                # Generally there should only be one ipv4 and one ipv6 address
                if addressPointer.next:
                    addressPointer = addressPointer.next.contents
                else:
                    addressPointer = False

            # All information we get from the pointer will be in binary
            # We employ bytes.decode() here
            name        = bytes.decode(devNamePointer.name)
            description = bytes.decode(devNamePointer.description) if devNamePointer.description else "(No description available)"

            # Push everything we just gathered into our adapter list
            adapters.append({
                'name'        : name,
                'description' : description,
                'ipv4'        : ip4,
                'ipv6'        : ip6
            })

            # Select the next adapter, break otherwise
            if devNamePointer.next:
                devNamePointer = devNamePointer.next.contents
            else:
                devNamePointer = False

        pcap_freealldevs(alldevs)

        if len(adapters) == 0:
            raise pcapError("pcap_findalldevs: No adapters found!")

        ##print("Gathered adapters")
        return adapters



    # listenAdapter will start listening on the selected adapter, but not sniff anything just yet
    # Takes the device name as an argument, ie `\\Device\\NPF_{258EC5CA-A7AE-4311-B35B-275B1A1C2E97}` as string
    # check object.adapters for these names
    def listenAdapter(self, adapterName):

        # Create a string to hold errors returned by pcap
        errbuf  = create_string_buffer(PCAP_ERRBUF_SIZE)

        # Set up the packet capturing using a pcap function
        ##pcap_open_live (const char *device, int snaplen, int promisc, int to_ms, char *ebuf)
        self._handle = pcap_open_live(
            bytes(adapterName, 'utf-8'),
            65536,  # Max packet size
            0,      # Promiscuous flag, we don't care about broadcasts
            1000,   # Time converter
            errbuf  # Error buffer
        )

        if self._handle == None:
            raise pcapError("pcap_open_live: Unable to listen on the selected adapter")

        ##print("Listened to", adapterName)

    # Start sniffing packets
    def start(self, packetNum=-1):
        ##print("Capturing started")

        if not self._handle:
            raise pcapError("Need to listen to an adapter first!!")

        self.isCapturing = True
        self._doNotLoop = False

        # Take a certain number of packets, or all of them (default)
        self._thread = threading.Thread(
            target = pcap_loop,
            args = (self._handle, packetNum, self._CFUNCpacketHandlerDefault, None)
        )

        self._thread.start()

    # Stop capturing, close the handle
    # This also ends the thread
    def stop(self):
        self._doNotLoop = True


# Dummy exception name class
class pcapError(Exception):
    pass


def example():
    mySniffer = PacketSniffer()
    adapters = mySniffer.adapters

    defaultAdapter = adapters[0]["name"]
    mySniffer.listenAdapter(defaultAdapter)

    mySniffer.onPacket = lambda self, packet: print( packet["decodedPayload"] )

    mySniffer.start()


if __name__ == "__main__":
    example()