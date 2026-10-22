# https://en.wikipedia.org/wiki/Ethernet_frame#Structure

import struct

from classes.constants.EtherTypes import ETHER_TYPES
from classes.utils.Formatters import format_mac


class EthernetFrame:
    # 14 = dest mac (6), src mac (6), ethertype/len (2)
    FRAME_HEADER_LEN = 14

    def __init__(self, data: bytes) -> None:
        self.frame_header, self.payload = self.process_frame(data)
        self.dest_mac, self.src_mac, self.ether_type = self.frame_header
        self.payload_len = len(self.payload)

    def process_frame(self, data: bytes):
        if len(data) < self.FRAME_HEADER_LEN:
            raise ValueError(
                f"Ethernet frame needs >= {self.FRAME_HEADER_LEN} bytes, got {len(data)}"
            )

        return (
            # first bytes is the header, split into tuple
            struct.unpack("!6s6sH", data[: self.FRAME_HEADER_LEN]),
            # after the header the rest of the data is the payload in the frame,
            # the checksum (FCS) is already stripped but any 0x00 padding to the
            # min size of 46 bytes is kept, the IP layer trims it using its length
            data[self.FRAME_HEADER_LEN :],
        )

    def __str__(self) -> str:
        # handle some nice formatting in the output plus descriptions
        ethertype_formatted = hex(self.ether_type)
        if self.ether_type in ETHER_TYPES:
            ethertype_formatted = (
                ethertype_formatted + ":" + ETHER_TYPES[self.ether_type]
            )

        return (
            f"|Frame > "
            + f"SourceMAC=[{format_mac(self.src_mac)}] "
            + f"DestinationMAC=[{format_mac(self.dest_mac)}] "
            + f"EtherType=[{ethertype_formatted}] "
        )
