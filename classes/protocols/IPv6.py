# https://en.wikipedia.org/wiki/IPv6_packet


import struct

from classes.constants.IPProtocols import IP_PROTOCOLS
from classes.utils.Formatters import format_ipv6


class IPv6:
    # 40 = version (0.5), traffic class (1), flow label (2.5), payload len (2),
    #   next header (1), hop limit (1), src addr (16), dest addr (16)
    FIXED_HEADER_LEN = 40

    def __init__(self, data: bytes) -> None:
        (
            self.VERSION_TRAFFIC_FLOW_RAW,
            self.PAYLOAD_LEN,
            self.NEXT_HEADER,
            self.HOP_LIMIT,
            self.SRC_IP_RAW,
            self.DEST_IP_RAW,
        ), self.PAYLOAD = self.process_packet(data)

        # process the VERSION, TRAFFIC_CLASS and FLOW_LABEL fields
        # 4 bytes = version (4 bits), traffic class (8 bits), flow label (20 bits)
        self.VERSION = self.VERSION_TRAFFIC_FLOW_RAW >> 28
        self.TRAFFIC_CLASS = (self.VERSION_TRAFFIC_FLOW_RAW >> 20) & 0xFF
        self.FLOW_LABEL = self.VERSION_TRAFFIC_FLOW_RAW & 0xFFFFF

        self.SRC_IP = format_ipv6(self.SRC_IP_RAW)
        self.DEST_IP = format_ipv6(self.DEST_IP_RAW)

    def process_packet(self, data: bytes):
        return (
            struct.unpack("!IHBB16s16s", data[: self.FIXED_HEADER_LEN]),
            # options and payload that needs to be processed
            data[self.FIXED_HEADER_LEN :],
        )

    def __str__(self) -> str:
        # handle some nice formatting in the output plus descriptions
        next_header_formatted = hex(self.NEXT_HEADER)

        if self.NEXT_HEADER in IP_PROTOCOLS:
            next_header_formatted = (
                next_header_formatted + ":" + IP_PROTOCOLS[self.NEXT_HEADER]
            )

        return (
            f"|_IPv6 > "
            + f"NextHeader=[{next_header_formatted}] "
            + f"SourceIP=[{self.SRC_IP}] "
            + f"DestinationIP=[{self.DEST_IP}] "
            + f"HopLimit=[{self.HOP_LIMIT}] "
            + f"PayloadLen=[{self.PAYLOAD_LEN}] "
        )
