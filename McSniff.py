"""

    McSniff - Lui Crowie, 2024

"""

from datetime import date, datetime
import socket, sys, signal

from classes.EthernetFrame import EthernetFrame
from classes.constants.EtherTypes import *
from classes.constants.IPProtocols import *
from classes.protocols.IPv4 import IPv4
from classes.protocols.UDP import UDP
from classes.protocols.TCP import TCP
from classes.utils.Formatters import *

# rudimentary tracking of frames, packets, ip proctols and time
STAT_COUNTS = {
    "start_time": None,
    "end_time": None,
    "frames": 0,
    "packets": 0,
    "segments": 0,
    "datagrams": 0,
}
# two updates = pull all new values without needing to update this
STAT_COUNTS.update({key: 0 for key in ETHER_TYPES_REVERSED.keys()}),
STAT_COUNTS.update({key: 0 for key in IP_PROTOCOLS_REVERSED.keys()}),


# easy way to manage 'all the things to do when quitting'
def do_exit(exit_code=0):
    print_yellow(f"[-] Statistics of session [{STAT_COUNTS}]")
    print_yellow("[X] Stopping McSniff!")
    sys.exit(exit_code)


# when we get a signal, handle accordingly
def exit_handler(signum, frame):
    print_yellow(f"[-] Handling SIGNAL=[{signal.Signals(signum).name}]...")

    # TODO - maybe consume and ignore some like SIGSTP?
    do_exit()


def update_stats(key, value=1):
    # for counts, append
    if type(value) is int:
        STAT_COUNTS[key] += value

    # for timestamps/time set new value
    if type(value) is str:
        STAT_COUNTS[key] = value


# handle all the magic in socket setup, and binding to interfaces
def setup_socket(interface_name) -> socket:
    # create the actual socket connection and bind to an interface
    try:
        # family - 17, low-level packet interface
        # type -  3, says on the tin, raw protocol access
        # protocol - ETH_P_ALL, give us every packet!
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        # dump out all interfaces
        print_yellow(
            f"[-] Avaliable interfaces are [{[interface[1] for interface in socket.if_nameindex()]}]"
        )

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
    # TODO - add arg parsing properly, for now just take sys.argv[1] as iface

    # capture ctrl+c (SIGINT)
    signal.signal(signal.SIGINT, exit_handler)
    # nice graceful kill -15's
    signal.signal(signal.SIGTERM, exit_handler)

    print_yellow("[+] Starting McSniff...")
    s = setup_socket("eth0")

    start_time = str(datetime.now())
    print_yellow(f"[-] Start time of sniffing [{start_time}]")
    update_stats("start_time", start_time)

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
        update_stats("frames")
        print(frame)

        # check if it's a ETHER type we can process
        if frame.ETHER_TYPE in ETHER_TYPES:

            # IPv4
            if frame.ETHER_TYPE == ETHER_TYPES_REVERSED["IPv4"]:
                ipv4 = IPv4(frame.PAYLOAD)
                update_stats("packets")
                update_stats("IPv4")
                print_green(f"{ipv4}")

                # TODO
                # TCP
                if ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["TCP"]:
                    update_stats("TCP")
                    tcp = TCP(ipv4.PAYLOAD)
                    print_blue(f"{tcp}")

                    # TODO - clean this up
                    if tcp.PAYLOAD_LEN > 0:
                        update_stats("segments")
                        print_blue("    \\_ PAYLOAD")
                        print_blue("       -------")
                        print_blue(tcp.PAYLOAD)
                        print_blue("       -------")

                # UDP
                if ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["UDP"]:
                    update_stats("UDP")
                    udp = UDP(ipv4.PAYLOAD)
                    print_blue(f"{udp}")

                    # TODO - clean this up
                    if udp.PAYLOAD_LEN > 0:
                        update_stats("datagrams")
                        print_blue("    \\_ PAYLOAD")
                        print_blue("       -------")
                        print_blue(udp.PAYLOAD)
                        print_blue("       -------")

                # TODO
                # ICMP
                if ipv4.PROTOCOL == IP_PROTOCOLS_REVERSED["ICMP"]:
                    update_stats("ICMP")
                    print_blue(f"  \\_ICMP >")

            # TODO
            # ARP
            if frame.ETHER_TYPE == ETHER_TYPES_REVERSED["ARP"]:
                update_stats("ARP")
                update_stats("packets")
                print_green("\\_   ARP > ")

            # TODO
            # RARP
            if frame.ETHER_TYPE == ETHER_TYPES_REVERSED["RARP"]:
                update_stats("RARP")
                update_stats("packets")
                print_green("\\_  RARP > ")

            # TODO
            # IPv6
            if frame.ETHER_TYPE == ETHER_TYPES_REVERSED["IPv6"]:
                update_stats("IPv6")
                update_stats("packets")
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
