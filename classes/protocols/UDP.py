# https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure

import struct


class UDP:
    # 8 = src port (2), dest port (2), length (2), checksum (2)
    PACKET_HEADER_LEN = 8

    def __init__(self, data: bytes) -> None:
        self.packet_header, self.payload = self.process_packet(data)
        self.src_port, self.dest_port, self.length, self.checksum = self.packet_header
        self.payload_len = len(self.payload)

    def process_packet(self, data: bytes):
        if len(data) < self.PACKET_HEADER_LEN:
            raise ValueError(
                f"UDP needs >= {self.PACKET_HEADER_LEN} bytes, got {len(data)}"
            )

        return (
            # first bytes is the header, split into tuple
            struct.unpack("!HHHH", data[: self.PACKET_HEADER_LEN]),
            # payload is the rest of the packet
            data[self.PACKET_HEADER_LEN :],
        )

    def __str__(self) -> str:
        return (
            f"|__UDP > "
            + f"SourcePort=[{self.src_port}] "
            + f"DestinationPort=[{self.dest_port}] "
            + f"Checksum=[{self.checksum}] "
            + f"PayloadLen=[{self.payload_len}] "
        )
