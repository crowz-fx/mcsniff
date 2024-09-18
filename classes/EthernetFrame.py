import struct

from classes.constants.EtherTypes import ETHER_TYPES
from classes.utils.Formatters import format_mac


class EthernetFrame:
    # 14 = dest mac (6), src mac (6), ethertype/len (2)
    FRAME_HEADER_LEN = 14

    def __init__(self, data) -> None:
        self.frame_header, self.payload = self.process_frame(data)
        self.DEST_MAC, self.SRC_MAC, self.ETHER_TYPE = self.frame_header
        self.PAYLOAD_LEN = len(self.payload)

    def process_frame(self, data):
        return (
            # first bytes is the header, split into tuple
            struct.unpack("!6s6sH", data[: self.FRAME_HEADER_LEN]),
            # after the header the rest of the data is the payload in the frame,
            # sockets library automagically removes the checksum and the 0x00
            # padding to the end (if < min size of 46 bytes)
            data[self.FRAME_HEADER_LEN :],
        )

    def __str__(self) -> str:
        # handle some nice formatting in the output plus descriptions
        ethertype_formatted = hex(self.ETHER_TYPE)
        if self.ETHER_TYPE in ETHER_TYPES:
            ethertype_formatted = (
                ethertype_formatted + ":" + ETHER_TYPES[self.ETHER_TYPE]
            )

        return (
            f"| Frame > DestinationMAC=[{format_mac(self.DEST_MAC)}], "
            + f"SourceMAC=[{format_mac(self.SRC_MAC)}], "
            + f"EtherType=[{ethertype_formatted}] |"
        )
