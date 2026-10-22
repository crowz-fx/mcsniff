# https://en.wikipedia.org/wiki/IPv4#Packet_structure

import struct
from classes.constants.IPProtocols import IP_PROTOCOLS
from classes.utils.Formatters import format_ipv4


class IPv4:
    # 20 = version & IHL (1), DSCP & ESC (1), total len (2)
    #      identification (4), flags & fragment offset (2)
    #      ttl (1), protocol (1), header checksum (2)
    #      src ip (4), dest ip (4)
    HEADER_REQUIRED_LEN = 20

    def __init__(self, data: bytes):
        self.required_header, unprocessed_data = self.process_packet(data)
        (
            self.version_ihl_raw,
            self.dscp_ecn_raw,
            self.length,
            self.identification,
            self.flags_offset_raw,
            self.time_to_live,
            self.protocol,
            self.checksum,
            self.src_ip_raw,
            self.dest_ip_raw,
        ) = self.required_header

        # now process out all specfics from processed bytes or format accordingly
        self.version = self.version_ihl_raw >> 4
        self.ihl = self.version_ihl_raw & 0x0F
        self.dscp = (self.dscp_ecn_raw & 0xFC) >> 2
        self.ecn = self.dscp_ecn_raw & 0x03
        self.flags = (self.flags_offset_raw & 0xE000) >> 13
        self.offset = self.flags_offset_raw & 0x1FFF
        self.src_ip = format_ipv4(self.src_ip_raw)
        self.dest_ip = format_ipv4(self.dest_ip_raw)

        # calculation options length, based off IHL, optional so default to 0
        self.options_len = 0
        if self.ihl > 5:
            self.options_len = (self.ihl - 5) * 4

        # TODO - should maybe catch if options is too big or can that never happen?

        header_len = self.HEADER_REQUIRED_LEN + self.options_len
        if self.length < header_len:
            raise ValueError(
                f"IPv4 total length {self.length} is smaller than its header {header_len}"
            )

        # total length marks the real end of the packet, anything after it is ethernet
        # padding, if fewer bytes arrived than it claims the slice keeps what we have
        packet_end = self.length - self.HEADER_REQUIRED_LEN

        # now we know options length (usually 0), now we know where the payload starts
        self.options = unprocessed_data[: self.options_len]
        self.payload = unprocessed_data[self.options_len : packet_end]
        self.payload_len = len(self.payload)

    def process_packet(self, data: bytes):
        if len(data) < self.HEADER_REQUIRED_LEN:
            raise ValueError(
                f"IPv4 needs >= {self.HEADER_REQUIRED_LEN} bytes, got {len(data)}"
            )

        return (
            struct.unpack("!BBHHHBBH4s4s", data[: self.HEADER_REQUIRED_LEN]),
            data[self.HEADER_REQUIRED_LEN :],
        )

    def __str__(self) -> str:
        # handle some nice formatting in the output plus descriptions
        protocol_formatted = hex(self.protocol)

        if self.protocol in IP_PROTOCOLS:
            protocol_formatted = protocol_formatted + ":" + IP_PROTOCOLS[self.protocol]

        return (
            f"|_IPv4 > "
            + f"Protocol=[{protocol_formatted}] "
            + f"SourceIP=[{self.src_ip}] "
            + f"DestinationIP=[{self.dest_ip}] "
            + f"TTL=[{self.time_to_live}] "
            + f"PayloadLen=[{self.payload_len}] "
        )
