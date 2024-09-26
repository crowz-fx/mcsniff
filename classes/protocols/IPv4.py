# https://en.wikipedia.org/wiki/IPv4#Packet_structure

import struct
from classes.constants.IPProtocols import *
from classes.utils.Formatters import *


class IPv4:
    # 20 = version & IHL (1), DSCP & ESC (1), total len (2)
    #      identification (4), flags & fragment offset (2)
    #      ttl (1), protocol (1), header checksum (2)
    #      src ip (4), dest ip (4)
    HEADER_REQUIRED_LEN = 20
    # 'options' handled below, is optional so default to 0
    HEADER_OPTIONS_LEN = 0

    def __init__(self, data: bytes):
        self.REQUIRED_HEADER, PACKET_UNPROCESSED_DATA = self.process_packet(data)
        (
            self.VERSION_IHL_RAW,
            self.DSCP_ECN_RAW,
            self.LENGTH,
            self.IDENTIFICATION,
            self.FLAGS_OFFSET_RAW,
            self.TIME_TO_LIVE,
            self.PROTOCOL,
            self.CHECKSUM,
            self.SRC_IP_RAW,
            self.DEST_IP_RAW,
        ) = self.REQUIRED_HEADER

        # now process out all specfics from processed bytes or format accordingly
        self.VERSION = self.VERSION_IHL_RAW >> 4
        self.IHL = self.VERSION_IHL_RAW & 0x0F
        self.DSCP = (self.DSCP_ECN_RAW & 0xFC) >> 2
        self.ECN = self.DSCP_ECN_RAW & 0x03
        self.FLAGS = (self.FLAGS_OFFSET_RAW & 0xE000) >> 13
        self.OFFSET = self.FLAGS_OFFSET_RAW & 0x1FFF
        self.SRC_IP = format_ipv4(self.SRC_IP_RAW)
        self.DEST_IP = format_ipv4(self.DEST_IP_RAW)

        # calculation options length, based off IHL
        if self.IHL > 5:
            self.HEADER_OPTIONS_LEN = (self.IHL - 5) * 4

        # TODO - should maybe catch if options is too big or can that never happen?

        # now we know options length (usually 0), now we know where the payload starts
        self.OPTIONS = PACKET_UNPROCESSED_DATA[: self.HEADER_OPTIONS_LEN]
        self.PAYLOAD = PACKET_UNPROCESSED_DATA[self.HEADER_OPTIONS_LEN :]
        self.PAYLOAD_LEN = len(self.PAYLOAD)

    def process_packet(self, data: bytes):
        return (
            struct.unpack("!BBHHHBBH4s4s", data[: self.HEADER_REQUIRED_LEN]),
            data[self.HEADER_REQUIRED_LEN :],
        )

    def __str__(self) -> str:
        # handle some nice formatting in the output plus descriptions
        protocol_formatted = hex(self.PROTOCOL)

        if self.PROTOCOL in IP_PROTOCOLS:
            protocol_formatted = protocol_formatted + ":" + IP_PROTOCOLS[self.PROTOCOL]

        return (
            f"|_IPv4 > "
            + f"Protocol=[{protocol_formatted}] "
            + f"SourceIP=[{self.SRC_IP}] "
            + f"DestinationIP=[{self.DEST_IP}] "
            + f"TTL=[{self.TIME_TO_LIVE}] "
            + f"PayloadLen=[{self.PAYLOAD_LEN}] "
        )
