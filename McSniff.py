"""

    McSniff - Lui Crowie, 2024

"""

from datetime import datetime
import socket, sys, signal, argparse

from classes.EthernetFrame import EthernetFrame
from classes.State import *
from classes.constants.EtherTypes import *
from classes.constants.IPProtocols import *
from classes.protocols.ARP import ARP
from classes.protocols.ICMP import ICMP
from classes.protocols.IPv4 import IPv4
from classes.protocols.IPv6 import IPv6
from classes.protocols.UDP import UDP
from classes.protocols.TCP import TCP
from classes.utils.Formatters import *


# easy way to manage 'all the things to do when quitting'
def do_exit(exit_code: int = 0):
    handle_time("end")

    if OPTIONS["statistics"]:
        # remove any time related stats for the output
        final_counts = (
            "".join(
                [
                    f"\n      {k}:{STAT_COUNTS[k]}"
                    for k in STAT_COUNTS.keys()
                    if not k.endswith("time")
                ],
            )
            + "\n"
        )
        print_yellow("[-] Statistics of session...")
        print_green(final_counts)

    print_yellow("[X] Stopping McSniff!")
    sys.exit(exit_code)


# when we get a signal, handle accordingly
def exit_handler(signum: signal.signal, frame):
    print_yellow(f"\n[-] Handling SIGNAL=[{signal.Signals(signum).name}]...")

    # TODO - maybe consume and ignore some like SIGSTP?
    do_exit()


def handle_time(classification: str):
    time_now = str(datetime.now())
    print_yellow(f"[-] {classification.capitalize()} time of sniffing [{time_now}]")
    update_stats(f"{classification.lower()}_time", time_now)


# handle all the magic in socket setup, and binding to interfaces
def setup_socket(interface_name: str) -> socket:
    # create the actual socket connection and bind to an interface
    try:
        # dump out all interfaces
        all_interfaces = [interface[1] for interface in socket.if_nameindex()]
        all_interfaces_formatted = ", ".join(all_interfaces)
        print_yellow(f"[-] Avaliable interfaces are [{all_interfaces_formatted}]")

        # family - 17, low-level packet interface
        # type -  3, says on the tin, raw protocol access
        # protocol - ETH_P_ALL, give us every packet!
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        # bind to a specific interface
        s.bind((interface_name, 0))

        interface_name, proto, packet_type, ha_type, address = s.getsockname()
        print_yellow(
            f"[-] Bound to interface=[{interface_name}], "
            + f"protocol=[{proto}], "
            + f"address=[{format_mac(address)}]"
        )

        return s
    except socket.error as error:
        print(
            f"Failed to create socket connection, error=[{str(error.errno)}], message=[{error.strerror}]"
        )
        do_exit(1)


# main entrypoint into the script
if __name__ == "__main__":
    args_parser = argparse.ArgumentParser(
        description="Network analyser (packet sniffer)... for you know, research purposes ;)"
    )

    args_parser.add_argument(
        "interface",
        type=str,
        help="interface to analyse, run 'ip link' to list",
        default=OPTIONS["interface"],
    )
    args_parser.add_argument(
        "-p",
        "--payload",
        help="dump payload output",
        action="store_true",
        required=False,
    )
    args_parser.add_argument(
        "-s",
        "--stats",
        help="enable and show statistics for what's been processed",
        action="store_true",
        required=False,
    )
    args_parser.add_argument(
        "-t",
        "--https",
        help="include dumps even for 443 port payloads (encrypted traffic)",
        action="store_true",
        required=False,
        default=False,
    )
    args_parser.add_argument(
        "-2",
        "--level2",
        help="OSI level 2 filter, by default listens for all, supply no args to ignore level",
        required=False,
        choices=OPTIONS["level2"],
        nargs="*",
    )
    args_parser.add_argument(
        "-3",
        "--level3",
        help="OSI level 3 filter, by default listens for all, supply no args to ignore level",
        required=False,
        choices=OPTIONS["level3"],
        nargs="*",
    )
    args_parser.add_argument(
        "-4",
        "--level4",
        help="OSI level 4 filter, by default listens for all, supply no args to ignore level",
        required=False,
        choices=OPTIONS["level4"],
        nargs="*",
    )

    args = args_parser.parse_args()
    OPTIONS["interface"] = args.interface
    OPTIONS["payload"] = args.payload
    OPTIONS["statistics"] = args.stats
    OPTIONS["https"] = args.https

    if args.level2 is not None:
        OPTIONS["level2"] = args.level2
    if args.level3 is not None:
        OPTIONS["level3"] = args.level3
    if args.level4 is not None:
        OPTIONS["level4"] = args.level4

    # capture ctrl+c (SIGINT)
    signal.signal(signal.SIGINT, exit_handler)
    # nice graceful kill -15's
    signal.signal(signal.SIGTERM, exit_handler)

    print_yellow("[+] Starting McSniff...")
    print_yellow(
        "[-] Parameters > "
        + f"interface=[{OPTIONS['interface']}] "
        + f"enableStatistics=[{OPTIONS['statistics']}] "
        + f"showPayload=[{OPTIONS['payload']}] "
        + f"show443InPayload=[{OPTIONS['https']}] "
    )
    print_yellow(
        "[-] Filters (shown==enabled) > "
        + f"level2=[{', '.join(OPTIONS['level2'])}] "
        + f"level3=[{', '.join(OPTIONS['level3'])}] "
        + f"level4=[{', '.join(OPTIONS['level4'])}] "
    )
    s = setup_socket(OPTIONS["interface"])
    handle_time("start")

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

        if "ETH" in OPTIONS["level2"]:
            frame = EthernetFrame(unprocessed_data)
            update_stats("frames")
            print(frame)

            # check if it's a ETHER type we can process
            if frame.ETHER_TYPE in ETHER_TYPES:

                # TODO - in payloads, search for things like user:pwds?

                # IPv4
                if (
                    frame.ETHER_TYPE == ETHER_TYPES_REVERSED["IPv4"]
                    and "IPv4" in OPTIONS["level3"]
                ):
                    ipv4 = IPv4(frame.PAYLOAD)
                    update_stats("packets")
                    update_stats("IPv4")
                    print_green(ipv4)

                    # TCP
                    if (
                        ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["TCP"]
                        and "TCP" in OPTIONS["level4"]
                    ):
                        update_stats("TCP")
                        tcp = TCP(ipv4.PAYLOAD)
                        print_blue(tcp)

                        if tcp.PAYLOAD_LEN > 0:
                            update_stats("segments")

                            if OPTIONS["https"] or (
                                tcp.DEST_PORT != 443 and tcp.SRC_PORT != 443
                            ):
                                print_payload(tcp.PAYLOAD)

                    # UDP
                    if (
                        ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["UDP"]
                        and "UDP" in OPTIONS["level4"]
                    ):
                        update_stats("UDP")
                        udp = UDP(ipv4.PAYLOAD)
                        print_blue(udp)

                        if udp.PAYLOAD_LEN > 0:
                            update_stats("datagrams")
                            print_payload(udp.PAYLOAD)

                    # ICMP
                    if (
                        ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["ICMP"]
                        and "ICMP" in OPTIONS["level3"]
                    ):
                        update_stats("ICMP")
                        icmp = ICMP(ipv4.PAYLOAD)
                        print_blue(icmp)

                        if icmp.PAYLOAD_LEN > 0:
                            update_stats("datagrams")
                            print_payload(icmp.PAYLOAD)

                    # IGMP
                    if (
                        ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["IGMP"]
                        and "IGMP" in OPTIONS["level3"]
                    ):
                        # TODO - implement IGMP
                        update_stats("IGMP")
                        update_stats("packets")
                        print_blue("|__IGMP > ")

                # TODO - maybe later ARP spoofing?

                # ARP
                if (
                    frame.ETHER_TYPE == ETHER_TYPES_REVERSED["ARP"]
                    and "ARP" in OPTIONS["level2"]
                ):
                    arp = ARP("ARP", frame.PAYLOAD)
                    update_stats("ARP")
                    update_stats("packets")
                    print_green(arp)
                    print_blue(f"|___PAYLOAD - [{arp.ARP_DESCRIPTION}]")

                # RARP
                if (
                    frame.ETHER_TYPE == ETHER_TYPES_REVERSED["RARP"]
                    and "RARP" in OPTIONS["level2"]
                ):
                    # same as ARP but different PTYPE
                    rarp = ARP("RARP", frame.PAYLOAD)
                    update_stats("RARP")
                    update_stats("packets")
                    print_green(rarp)

                # IPv6
                if (
                    frame.ETHER_TYPE == ETHER_TYPES_REVERSED["IPv6"]
                    and "IPv6" in OPTIONS["level3"]
                ):
                    update_stats("IPv6")
                    update_stats("packets")
                    ipv6 = IPv6(frame.PAYLOAD)
                    print_green(ipv6)

                    # # ICMP
                    if (
                        ipv6.NEXT_HEADER == IP_PROTOCOLS_REVERSED["ICMPv6"]
                        and "ICMPv6" in OPTIONS["level3"]
                    ):
                        # TODO - implement ICMPv6
                        print_blue(f"|__ICMPv6 >")

                    # TCP
                    if (
                        ipv6.NEXT_HEADER == IP_PROTOCOLS_REVERSED["TCP"]
                        and "TCP" in OPTIONS["level4"]
                    ):
                        update_stats("TCP")
                        tcp = TCP(ipv6.PAYLOAD)
                        print_blue(tcp)

                        if tcp.PAYLOAD_LEN > 0:
                            update_stats("segments")

                            if OPTIONS["https"] or (
                                tcp.DEST_PORT != 443 and tcp.SRC_PORT != 443
                            ):
                                print_payload(tcp.PAYLOAD)

                    # UDP
                    if (
                        ipv6.NEXT_HEADER == IP_PROTOCOLS_REVERSED["UDP"]
                        and "UDP" in OPTIONS["level4"]
                    ):
                        update_stats("UDP")
                        udp = UDP(ipv6.PAYLOAD)
                        print_blue(udp)

                        if udp.PAYLOAD_LEN > 0:
                            update_stats("datagrams")
                            print_payload(udp.PAYLOAD)

            print()
