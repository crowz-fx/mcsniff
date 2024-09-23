# https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure

import struct

from classes.constants.EtherTypes import ETHER_TYPES
from classes.utils.Formatters import format_ipv4, format_mac


class ARP:
    # there is no header len as the whole packets is considered the payload

    def __init__(self, arp_type: str, data: bytes) -> None:
        self.ARP_TYPE = arp_type
        (
            self.HARDWARE_TYPE,
            self.PROTOCOL_TYPE,
            self.HARDWARE_ADDR_LEN,
            self.PROTOCOL_ADDR_LEN,
            self.OPERATION,
            self.SENDER_HARDWARE_ADDR,
            self.SENDER_PROTOCOL_ADDR,
            self.TARGET_HARDWARE_ADDR,
            self.TARGET_PROTOCOL_ADDR,
        ) = self.process_packet(data)

    def process_packet(self, data: bytes):
        return struct.unpack("!HHBBH6s4s6s4s", data)

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
            # + f"HardwareAddrLen=[{self.HARDWARE_ADDR_LEN}] "
            # + f"ProtocolAddrLen=[{self.PROTOCOL_ADDR_LEN}] "
            + f"Operation=[{operation_formatted}] "
            + f"SenderHardwareAddr=[{format_mac(self.SENDER_HARDWARE_ADDR)}] "
            + f"SenderProtocolAddr=[{format_ipv4(self.SENDER_PROTOCOL_ADDR)}] "
            + f"TargetHardwareAddr=[{format_mac(self.TARGET_HARDWARE_ADDR)}] "
            + f"TargetProtocolAddr=[{format_ipv4(self.TARGET_PROTOCOL_ADDR)}] "
        )
