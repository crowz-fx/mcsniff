# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Datagram_structure

import struct

from classes.constants.ControlMessages import CONTROL_MESSAGES
from classes.utils.Formatters import format_payload


class ICMP:
    # 8 = type (1), code (1), checksum (2), rest of header (4)
    HEADER_LEN = 8

    def __init__(self, data: bytes) -> None:
        self.PACKET_HEADER, self.RAW_PAYLOAD = self.process_packet(data)
        self.TYPE, self.CODE, self.CHECKSUM, self.REST_OF_HEADER = self.PACKET_HEADER

        self.PAYLOAD = format_payload(self.RAW_PAYLOAD)
        self.PAYLOAD_LEN = len(self.RAW_PAYLOAD)
        self.PAYLOAD_INFO = (
            "Typically random chars or if error then the IPv4/6 that caused it"
        )

    def process_packet(self, data: bytes):
        return (
            # header
            struct.unpack("!BBH4s", data[: self.HEADER_LEN]),
            # payload, this is usually random ascii or trash sent in echo/reply req/reply
            data[self.HEADER_LEN :],
        )

    def __str__(self) -> str:
        type_formatted = f"{self.TYPE}"
        code_formatted = f"{self.CODE}"
        rest_of_header_formatted = f"{self.REST_OF_HEADER}"

        # handle some nice formatting of types and code (if they are mapped)
        control_message = CONTROL_MESSAGES[self.TYPE]
        if control_message:
            # append nice message type description
            type_formatted += ":" + control_message["value"]

            # if the type has subcodes then append to format
            if "codes" in control_message.keys():
                code_formatted += ":" + control_message["codes"][self.CODE]

            # if echo req/reply
            if self.TYPE == 8 or self.TYPE == 0:
                # rest of header for these are broken into identifier (2), seq num (2)
                rest_of_header_unpacked = struct.unpack("!HH", self.REST_OF_HEADER)
                rest_of_header_formatted = (
                    "Identifier:"
                    + str(rest_of_header_unpacked[0])
                    + "//"
                    + "SequenceNo:"
                    + str(rest_of_header_unpacked[1])
                )

            # TODO - maybe add deeper processing ofr time exceeded, unreachable, timestamp

        return (
            f"  \\_ICMP > "
            + f"Type=[{type_formatted}] "
            + f"Code=[{code_formatted}] "
            + f"CheckSum=[{self.CHECKSUM}] "
            + f"RestOfHeader=[{rest_of_header_formatted}] "
        )
