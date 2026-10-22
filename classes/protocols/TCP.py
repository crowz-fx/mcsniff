# https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure

import struct


class TCP:
    # 20 = src port (2), dest port (2), seq no (4), ack no (4),
    #      data offset & reserved (1), flags (1), window (2),
    #      checksum(2), urgent pointer (2)
    PACKET_HEADER_LEN = 20

    def __init__(self, data: bytes) -> None:
        self.packet_header, unprocessed_data = self.process_packet(data)
        (
            self.src_port,
            self.dest_port,
            self.sequence_no,
            self.acknowledge_no,
            self.raw_flags_and_offset,
            self.window_size,
            self.checksum,
            self.urgent_pointer,
        ) = self.packet_header

        # size of TCP header in 32-bit words
        self.offset = self.raw_flags_and_offset >> 12
        # this is reserved but not implemented
        self.nonce_sum = bool((self.raw_flags_and_offset >> 8) & 0x01)
        # control bits in order they appear in the header
        self.flags = {
            "CWR": (self.raw_flags_and_offset >> 7) & 0x01,
            "ECE": (self.raw_flags_and_offset >> 6) & 0x01,
            "URG": (self.raw_flags_and_offset >> 5) & 0x01,
            "ACK": (self.raw_flags_and_offset >> 4) & 0x01,
            "PSH": (self.raw_flags_and_offset >> 3) & 0x01,
            "RST": (self.raw_flags_and_offset >> 2) & 0x01,
            "SYN": (self.raw_flags_and_offset >> 1) & 0x01,
            "FIN": self.raw_flags_and_offset & 0x01,
        }

        # options are optional so default to 0
        self.options_len = 0
        if self.offset > 5:
            self.options_len = (self.offset - 5) * 4

        self.options = unprocessed_data[: self.options_len]
        self.payload = unprocessed_data[self.options_len :]
        self.payload_len = len(self.payload)

    def process_packet(self, data: bytes):
        if len(data) < self.PACKET_HEADER_LEN:
            raise ValueError(
                f"TCP needs >= {self.PACKET_HEADER_LEN} bytes, got {len(data)}"
            )

        return (
            # strip header into its parts for further processing
            struct.unpack("!HHIIHHHH", data[: self.PACKET_HEADER_LEN]),
            # payload
            data[self.PACKET_HEADER_LEN :],
        )

    def __str__(self) -> str:
        # process the flags, only show ones that are actually enabled
        flags_processed = ",".join(
            flag_key for flag_key in self.flags.keys() if self.flags[flag_key]
        )

        return (
            f"|__TCP > "
            + f"SourcePort=[{self.src_port}] "
            + f"DestinationPort=[{self.dest_port}] "
            + f"Flags=[{flags_processed}] "
            + f"SeqNo=[{self.sequence_no}] "
            + f"AckNo=[{self.acknowledge_no}] "
            + f"PayloadLen=[{self.payload_len}] "
            + f"Checksum=[{self.checksum}] "
        )
