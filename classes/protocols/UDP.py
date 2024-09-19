# https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure

import struct


class UDP:
    # 8 = src port (2), dest port (2), length (2), checksum (2)
    PACKET_HEADER_LEN = 8

    def __init__(self, data) -> None:
        self.PACKET_HEADER, self.PAYLOAD = self.process_packet(data)
        self.SRC_PORT, self.DEST_PORT, self.LENGTH, self.CHECKSUM = self.PACKET_HEADER
        self.PAYLOAD_LEN = len(self.PAYLOAD)

    def process_packet(self, data):
        return (
            # first bytes is the header, split into tuple
            struct.unpack("!HHHH", data[: self.PACKET_HEADER_LEN]),
            # payload is the rest of the packet
            data[self.PACKET_HEADER_LEN :],
        )

    def __str__(self) -> str:
        return (
            f"\\_   UDP > "
            + f"SourcePort=[{self.SRC_PORT}], "
            + f"DestinationPort=[{self.DEST_PORT}], "
            + f"Length=[{self.PAYLOAD_LEN}] "
            + f"Checksum=[{self.CHECKSUM}] "
        )
