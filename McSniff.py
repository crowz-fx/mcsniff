"""

    McSniff - Lui Crowie, 2024

"""

import socket, sys, signal, os

from classes.EthernetFrame import EthernetFrame
from classes.constants.EtherTypes import *
from classes.constants.IPProtocols import *
from classes.protocols.IPv4 import IPv4
from classes.protocols.UDP import UDP
from classes.protocols.TCP import TCP
from classes.utils.Formatters import *


# easy way to manage 'all the things to do when quitting'
def do_exit(exit_code=0):
    print_yellow("[X] Stopping McSniff!")
    sys.exit(exit_code)


# when we get a signal, handle accordingly
def exit_handler(signum, frame):
    print_yellow(f"[+] Handling SIGNAL=[{signal.Signals(signum).name}]...")

    # TODO - maybe consume and ignore some like SIGSTP?
    do_exit()


# capture ctrl+c (SIGINT)
signal.signal(signal.SIGINT, exit_handler)
# nice graceful kill -15's
signal.signal(signal.SIGTERM, exit_handler)

print_yellow("[+] Starting McSniff...")

# create the actual socket connection and bind to an interface
try:
    # family - 17, low-level packet interface
    # type -  3, says on the tin, raw protocol access
    # protocol - ETH_P_ALL, give us every packet!
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    # dump out all interfaces
    print_yellow(
        f"[-] Avaliable interfaces are [{[interface[1] for interface in socket.if_nameindex()]}]..."
    )

    # bind to a specific interface
    # TODO - handle diff interfaces
    s.bind(("eth0", 0))

    interface_name, proto, packet_type, ha_type, address = s.getsockname()
    print_yellow(
        f"[-] Bound to interface=[{interface_name}], "
        + f"protocol=[{proto}], "
        + f"address=[{format_mac(address)}]"
    )
except socket.error as error:
    print(
        f"Failed to create socket connection, error=[{str(error.errno)}], message=[{error.strerror}]"
    )
    do_exit(1)

# loop and process each packet recieved
while True:
    # more than max packet size, even if eth frames are much lower
    # tuple = (bytes, return address), pull raw data
    try:
        unprocessed_data, address = s.recvfrom(65565)
    except KeyboardInterrupt as error:
        # pass due to SIGINT being handled in signalsabove, this is
        # to supress the stacktrace for the KeyboardInterrupt
        pass

    frame = EthernetFrame(unprocessed_data)
    print(frame)

    # check if it's a ETHER type we can process
    if frame.ETHER_TYPE in ETHER_TYPES:

        # IPv4
        if frame.ETHER_TYPE == ETHER_TYPES_REVERSED["IPv4"]:
            ipv4 = IPv4(frame.PAYLOAD)
            print_green(f"{ipv4}")

            # TODO
            # TCP
            if ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["TCP"]:
                tcp = TCP(ipv4.PAYLOAD)
                print_blue(f"{tcp}")

                # TODO - clean this up
                if tcp.PAYLOAD_LEN > 0:
                    print_blue("    \\_ PAYLOAD")
                    print_blue("       -------")
                    print_blue(tcp.PAYLOAD)
                    print_blue("       -------")

            # UDP
            if ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["UDP"]:
                udp = UDP(ipv4.PAYLOAD)
                print_blue(f"{udp}")

                # TODO - clean this up
                if udp.PAYLOAD_LEN > 0:
                    print_blue("    \\_ PAYLOAD")
                    print_blue("       -------")
                    print_blue(udp.PAYLOAD)
                    print_blue("       -------")

            # TODO
            # ICMP
            if ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["ICMP"]:
                print_blue(f"  \\_ICMP >")

        # TODO
        # ARP
        if frame.ETHER_TYPE == ETHER_TYPES_REVERSED["ARP"]:
            print_green("\\_   ARP > ")

        # TODO
        # RARP
        if frame.ETHER_TYPE == ETHER_TYPES_REVERSED["RARP"]:
            print_green("\\_  RARP > ")

        # TODO
        # IPv6
        if frame.ETHER_TYPE == ETHER_TYPES_REVERSED["IPv6"]:
            print_green("\\_  IPv6 > ")

            # # TODO
            # # TCP
            # if ipv6.PROTOCOL == IP_PROTOCOLS_REVERSED["TCP"]:
            #     print_blue(f"  \\_ TCP >")

            # # TODO
            # # UDP
            # if ipv6.PROTOCOL == IP_PROTOCOLS_REVERSED["UDP"]:
            #     print_blue(f"  \\_ UDP >")

            # # TODO
            # # ICMP
            # if ipv6.PROTOCOL == IP_PROTOCOLS_REVERSED["ICMPv6"]:
            #     print_blue(f"  \\_ICMPv6 >")
