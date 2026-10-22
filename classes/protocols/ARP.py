# https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure

import struct

from classes.constants.EtherTypes import ETHER_TYPES
from classes.constants.ARPOperationCodes import ARP_OPERATIONS
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
        self.arp_type = arp_type
        (
            self.hardware_type,
            self.protocol_type,
            self.hardware_addr_len,
            self.protocol_addr_len,
            self.operation,
        ), unprocessed_header = self.process_packet(data)

        # determine if possible, what type of ARP, set before branch so always exists
        self.arp_description = "ARP:Unknown"

        # only process IPv4 over Ethernet ARP messages
        if self.hardware_addr_len != 6 or self.protocol_addr_len != 4:
            (
                self.sender_hardware_addr,
                self.sender_protocol_addr,
                self.target_hardware_addr,
                self.target_protocol_addr,
            ) = (None, None, None, None)
        else:
            addresses_len = self.MAX_HEADER_LEN - self.FIXED_HEADER_LEN
            if len(unprocessed_header) < addresses_len:
                raise ValueError(
                    f"{self.arp_type} addresses need >= {addresses_len} bytes, "
                    + f"got {len(unprocessed_header)}"
                )

            (
                self.sender_hardware_addr_raw,
                self.sender_protocol_addr_raw,
                self.target_hardware_addr_raw,
                self.target_protocol_addr_raw,
            ) = struct.unpack(
                "!6s4s6s4s",
                unprocessed_header[:addresses_len],
            )

            self.sender_hardware_addr = format_mac(self.sender_hardware_addr_raw)
            self.sender_protocol_addr = format_ipv4(self.sender_protocol_addr_raw)
            self.target_hardware_addr = format_mac(self.target_hardware_addr_raw)
            self.target_protocol_addr = format_ipv4(self.target_protocol_addr_raw)

            if self.operation == 1:
                if self.target_hardware_addr == "00:00:00:00:00:00":
                    if self.sender_protocol_addr == self.target_protocol_addr:
                        self.arp_description = "ARP:Announcement"
                    elif self.sender_protocol_addr == "0.0.0.0":
                        self.arp_description = "ARP:Probe"
                    else:
                        self.arp_description = "ARP:Request"
                else:
                    self.arp_description = "ARP:Request"
            elif self.operation == 2:
                if (
                    self.sender_protocol_addr == self.target_protocol_addr
                    and self.target_hardware_addr == "00:00:00:00:00:00"
                ):
                    self.arp_description = "ARP:Gratuitous"
                else:
                    self.arp_description = "ARP:Reply"

    def process_packet(self, data: bytes):
        if len(data) < self.FIXED_HEADER_LEN:
            raise ValueError(
                f"{self.arp_type} needs >= {self.FIXED_HEADER_LEN} bytes, got {len(data)}"
            )

        return (
            struct.unpack("!HHBBH", data[: self.FIXED_HEADER_LEN]),
            data[self.FIXED_HEADER_LEN :],
        )

    def __str__(self) -> str:
        # yes the space for formatting in ARP
        arp_type_formatted = " ARP" if self.arp_type == "ARP" else "RARP"

        hardware_type_formatted = str(self.hardware_type)
        if self.hardware_type == 1:
            hardware_type_formatted += ":Eth"

        protocol_type_formatted = str(self.protocol_type)

        if self.protocol_type in ETHER_TYPES:
            protocol_type_formatted += ":" + str(ETHER_TYPES[self.protocol_type])

        operation_formatted = str(self.operation)
        if self.operation in ARP_OPERATIONS:
            operation_formatted += ":" + ARP_OPERATIONS[self.operation]

        return (
            f"|_{arp_type_formatted} > "
            + f"HardwareType=[{hardware_type_formatted}] "
            + f"ProtocolType=[{protocol_type_formatted}] "
            + f"HardwareAddrLen=[{self.hardware_addr_len}] "
            + f"ProtocolAddrLen=[{self.protocol_addr_len}] "
            + f"Operation=[{operation_formatted}] "
            + f"SenderHardwareAddr=[{self.sender_hardware_addr}] "
            + f"SenderProtocolAddr=[{self.sender_protocol_addr}] "
            + f"TargetHardwareAddr=[{self.target_hardware_addr}] "
            + f"TargetProtocolAddr=[{self.target_protocol_addr}] "
        )
