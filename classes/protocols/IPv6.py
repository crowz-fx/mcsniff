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
            self.version_traffic_flow_raw,
            self.payload_len,
            self.next_header,
            self.hop_limit,
            self.src_ip_raw,
            self.dest_ip_raw,
        ), self.payload = self.process_packet(data)

        # payload length marks the real end of the packet, anything after it is ethernet
        # padding, if fewer bytes arrived than it claims the slice keeps what we have
        self.payload = self.payload[: self.payload_len]

        # process the version, traffic class and flow label fields
        # 4 bytes = version (4 bits), traffic class (8 bits), flow label (20 bits)
        self.version = self.version_traffic_flow_raw >> 28
        self.traffic_class = (self.version_traffic_flow_raw >> 20) & 0xFF
        self.flow_label = self.version_traffic_flow_raw & 0xFFFFF

        self.src_ip = format_ipv6(self.src_ip_raw)
        self.dest_ip = format_ipv6(self.dest_ip_raw)

    def process_packet(self, data: bytes):
        if len(data) < self.FIXED_HEADER_LEN:
            raise ValueError(
                f"IPv6 needs >= {self.FIXED_HEADER_LEN} bytes, got {len(data)}"
            )

        return (
            struct.unpack("!IHBB16s16s", data[: self.FIXED_HEADER_LEN]),
            # options and payload that needs to be processed
            data[self.FIXED_HEADER_LEN :],
        )

    def __str__(self) -> str:
        # handle some nice formatting in the output plus descriptions
        next_header_formatted = hex(self.next_header)

        if self.next_header in IP_PROTOCOLS:
            next_header_formatted = (
                next_header_formatted + ":" + IP_PROTOCOLS[self.next_header]
            )

        return (
            f"|_IPv6 > "
            + f"NextHeader=[{next_header_formatted}] "
            + f"SourceIP=[{self.src_ip}] "
            + f"DestinationIP=[{self.dest_ip}] "
            + f"HopLimit=[{self.hop_limit}] "
            + f"PayloadLen=[{self.payload_len}] "
        )
