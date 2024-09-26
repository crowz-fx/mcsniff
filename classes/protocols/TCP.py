# https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure

import struct

from classes.utils.Formatters import format_payload


class TCP:
    # 20 = src port (2), dest port (2), seq no (4), ack no (4),
    #      data offset & reserved (1), flags (1), window (2),
    #      checksum(2), urgent pointer (2)
    PACKET_HEADER_LEN = 20
    # 'options' handled below, is optional so default to 0
    PACKET_OPTIONS_LEN = 0

    def __init__(self, data: bytes) -> None:
        self.PACKET_HEADER, PACKET_UNPROCESSED_DATA = self.process_packet(data)
        (
            self.SRC_PORT,
            self.DEST_PORT,
            self.SEQUENCE_NO,
            self.ACKNOWLEGE_NO,
            self.RAW_FLAGS_AND_OFFSET,
            self.WINDOW_SIZE,
            self.CHECKSUM,
            self.URGENT_POINTER,
        ) = self.PACKET_HEADER

        # size of TCP header in 32-bit words
        self.OFFSET = self.RAW_FLAGS_AND_OFFSET >> 12
        # this is reserved but not implemented
        self.NONCE_SUM = bool((self.RAW_FLAGS_AND_OFFSET >> 8) & 0x01)
        # control bits in order they appear in the header
        self.FLAGS = {
            "CWR": (self.RAW_FLAGS_AND_OFFSET >> 7) & 0x01,
            "ECE": (self.RAW_FLAGS_AND_OFFSET >> 6) & 0x01,
            "URG": (self.RAW_FLAGS_AND_OFFSET >> 5) & 0x01,
            "ACK": (self.RAW_FLAGS_AND_OFFSET >> 4) & 0x01,
            "PSH": (self.RAW_FLAGS_AND_OFFSET >> 3) & 0x01,
            "RST": (self.RAW_FLAGS_AND_OFFSET >> 2) & 0x01,
            "SYN": (self.RAW_FLAGS_AND_OFFSET >> 1) & 0x01,
            "FIN": self.RAW_FLAGS_AND_OFFSET & 0x01,
        }

        if self.OFFSET > 5:
            self.PACKET_OPTIONS_LEN = (self.OFFSET - 5) * 4

        self.PARAMS = PACKET_UNPROCESSED_DATA[: self.PACKET_OPTIONS_LEN]
        self.RAW_PAYLOAD = PACKET_UNPROCESSED_DATA[self.PACKET_OPTIONS_LEN :]
        self.PAYLOAD = format_payload(self.RAW_PAYLOAD)
        self.PAYLOAD_LEN = len(self.PAYLOAD)

    def process_packet(self, data: bytes):
        return (
            # strip header into its parts for further processing
            struct.unpack("!HHIIHHHH", data[: self.PACKET_HEADER_LEN]),
            # payload
            data[self.PACKET_HEADER_LEN :],
        )

    def __str__(self) -> str:
        # process the flags, only show ones that are actually enabled
        flags_processed = ",".join(
            flag_key for flag_key in self.FLAGS.keys() if self.FLAGS[flag_key]
        )

        return (
            f"|__TCP > "
            + f"SourcePort=[{self.SRC_PORT}] "
            + f"DestinationPort=[{self.DEST_PORT}] "
            + f"Flags=[{flags_processed}] "
            + f"SeqNo=[{self.SEQUENCE_NO}] "
            + f"AckNo=[{self.ACKNOWLEGE_NO}] "
            + f"PayloadLen=[{self.PAYLOAD_LEN}] "
            + f"Checksum=[{self.CHECKSUM}] "
        )
