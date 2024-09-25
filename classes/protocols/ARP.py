# https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure

import struct

from classes.constants.EtherTypes import ETHER_TYPES
from classes.utils.Formatters import format_ipv4, format_mac


class ARP:
    """Types of ARP
    - ARP / RARP (Reverse ARP) / Proxy ARP - identical, can't tell
        - request - OP = 1, sender MAC & IP set, target IP set, target MAC is broadcast/00
        - reply - OP = 2, all fields are set to their valuesq
    - ARP Annoucement - OP = 1, sender & target IP identical, target MAC is broadcast/00
    - Gratuitous ARP - OP = 2, sender & target IP identical, target MAC is broadcast/00
    - ARP Probe - OP = 1, sender MAC & target IP is not 0/0 or
    - Inverse ARP (InARP)
    """

    # Note - there is no payload for ARP, the whole packet is interchangable with header
    # the 'fixed' and guranteed to be same format fields in the header
    FIXED_HEADER_LEN = 8
    # size of packet is 28 bytes max, rest is paddding or can be ignored
    MAX_HEADER_LEN = 28

    def __init__(self, arp_type: str, data: bytes) -> None:
        self.ARP_TYPE = arp_type
        (
            self.HARDWARE_TYPE,
            self.PROTOCOL_TYPE,
            self.HARDWARE_ADDR_LEN,
            self.PROTOCOL_ADDR_LEN,
            self.OPERATION,
        ), UNPROCESSED_HEADER = self.process_packet(data)

        # only process IPv4 over Ethernet ARP messages
        if self.HARDWARE_ADDR_LEN != 6 or self.PROTOCOL_ADDR_LEN != 4:
            (
                self.SENDER_HARDWARE_ADDR,
                self.SENDER_PROTOCOL_ADDR,
                self.TARGET_HARDWARE_ADDR,
                self.TARGET_PROTOCOL_ADDR,
            ) = (None, None, None, None)
        else:
            (
                self.SENDER_HARDWARE_ADDR_RAW,
                self.SENDER_PROTOCOL_ADDR_RAW,
                self.TARGET_HARDWARE_ADDR_RAW,
                self.TARGET_PROTOCOL_ADDR_RAW,
            ) = struct.unpack(
                "!6s4s6s4s",
                UNPROCESSED_HEADER[: self.MAX_HEADER_LEN - self.FIXED_HEADER_LEN],
            )

            self.SENDER_HARDWARE_ADDR = format_mac(self.SENDER_HARDWARE_ADDR_RAW)
            self.SENDER_PROTOCOL_ADDR = format_ipv4(self.SENDER_PROTOCOL_ADDR_RAW)
            self.TARGET_HARDWARE_ADDR = format_mac(self.TARGET_HARDWARE_ADDR_RAW)
            self.TARGET_PROTOCOL_ADDR = format_ipv4(self.TARGET_PROTOCOL_ADDR_RAW)

            # determine if possible, what type of ARP
            self.ARP_DESCRIPTION = "ARP:Unknown"

            if self.OPERATION == 1:
                if self.TARGET_HARDWARE_ADDR == "00:00:00:00:00:00":
                    if self.SENDER_PROTOCOL_ADDR == self.TARGET_PROTOCOL_ADDR:
                        self.ARP_DESCRIPTION = "ARP:Announcement"
                    elif self.SENDER_PROTOCOL_ADDR == "0.0.0.0":
                        self.ARP_DESCRIPTION = "ARP:Probe"
                else:
                    self.ARP_DESCRIPTION = "ARP:Request"
            elif self.OPERATION == 2:
                if (
                    self.SENDER_PROTOCOL_ADDR == self.TARGET_PROTOCOL_ADDR
                    and self.TARGET_HARDWARE_ADDR == "00:00:00:00:00:00"
                ):
                    self.ARP_DESCRIPTION = "ARP:Gratuitous"
                else:
                    self.ARP_DESCRIPTION = "ARP:Reply"

    def process_packet(self, data: bytes):
        return (
            struct.unpack("!HHBBH", data[: self.FIXED_HEADER_LEN]),
            data[self.FIXED_HEADER_LEN :],
        )

    def __str__(self) -> str:
        # yes the space for formatting in ARP
        arp_type_formatted = " ARP" if self.ARP_TYPE == "ARP" else "RARP"

        hardware_type_formatted = str(self.HARDWARE_TYPE)
        if self.HARDWARE_TYPE == 1:
            hardware_type_formatted += ":Eth"

        protocol_type_formatted = str(self.PROTOCOL_TYPE)

        if ETHER_TYPES[self.PROTOCOL_TYPE]:
            protocol_type_formatted += ":" + str(ETHER_TYPES[self.PROTOCOL_TYPE])

        operation_formatted = "1:Request" if self.OPERATION == 1 else "2:Reply"

        return (
            f"\\_  {arp_type_formatted} > "
            + f"HardwareType=[{hardware_type_formatted}] "
            + f"ProtocolType=[{protocol_type_formatted}] "
            + f"HardwareAddrLen=[{self.HARDWARE_ADDR_LEN}] "
            + f"ProtocolAddrLen=[{self.PROTOCOL_ADDR_LEN}] "
            + f"Operation=[{operation_formatted}] "
            + f"SenderHardwareAddr=[{self.SENDER_HARDWARE_ADDR}] "
            + f"SenderProtocolAddr=[{self.SENDER_PROTOCOL_ADDR}] "
            + f"TargetHardwareAddr=[{self.TARGET_HARDWARE_ADDR}] "
            + f"TargetProtocolAddr=[{self.TARGET_PROTOCOL_ADDR}] "
        )
