# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Datagram_structure

import struct

from classes.constants.ControlMessages import CONTROL_MESSAGES


class ICMP:
    # 8 = type (1), code (1), checksum (2), rest of header (4)
    HEADER_LEN = 8

    def __init__(self, data: bytes) -> None:
        self.packet_header, self.payload = self.process_packet(data)
        self.type, self.code, self.checksum, self.rest_of_header = self.packet_header

        self.payload_len = len(self.payload)
        self.payload_info = (
            "Typically random chars or if error then the IPv4/6 that caused it"
        )

    def process_packet(self, data: bytes):
        if len(data) < self.HEADER_LEN:
            raise ValueError(f"ICMP needs >= {self.HEADER_LEN} bytes, got {len(data)}")

        return (
            # header
            struct.unpack("!BBH4s", data[: self.HEADER_LEN]),
            # payload, this is usually random ascii or trash sent in echo/reply req/reply
            data[self.HEADER_LEN :],
        )

    def __str__(self) -> str:
        type_formatted = f"{self.type}"
        code_formatted = f"{self.code}"
        rest_of_header_formatted = f"{self.rest_of_header}"

        # handle some nice formatting of types and code (if they are mapped)
        control_message = CONTROL_MESSAGES.get(self.type)
        if control_message:
            # append nice message type description
            type_formatted += ":" + control_message["value"]

            # if the type has subcodes then append to format, unmapped show number only
            code_description = control_message.get("codes", {}).get(self.code)
            if code_description:
                code_formatted += ":" + code_description

            # if echo req/reply
            if self.type == 8 or self.type == 0:
                # rest of header for these are broken into identifier (2), seq num (2)
                rest_of_header_unpacked = struct.unpack("!HH", self.rest_of_header)
                rest_of_header_formatted = (
                    "Identifier:"
                    + str(rest_of_header_unpacked[0])
                    + "//"
                    + "SequenceNo:"
                    + str(rest_of_header_unpacked[1])
                )

            # TODO - maybe add deeper processing for time exceeded, unreachable, timestamp

        return (
            f"|_ICMP > "
            + f"Type=[{type_formatted}] "
            + f"Code=[{code_formatted}] "
            + f"CheckSum=[{self.checksum}] "
            + f"RestOfHeader=[{rest_of_header_formatted}] "
        )
