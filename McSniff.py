"""

    McSniff - Lui Crowie, 2024

"""

import socket, sys
import struct

# use the hex values like in the standard
# https://en.wikipedia.org/wiki/EtherType#Values
ETHERTYPES = {
    # TODO - add in the rest
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6"
}

def format_mac(data):
    # 02 = pad with 0's till 2 chars, X = uppercase hex
    return ":".join(format(b, '02X') for b in data)

# create the actual socket connection and bind to an interface
try:
    """
     - socket info - https://www.man7.org/linux/man-pages/man2/socket.2.html
     - family - 17, low-level packet interface
     - type -  3, says on the tin, raw protocol access
     - protocol - ETH_P_ALL, give us every packet!
    """
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    # bind to a specific interface
    s.bind(("eth0", 0))
except socket.error as error:
    print(
        f"Failed to create socket connection, error=[{str(error.errno)}], message=[{error.strerror}]"
    )
    sys.exit()

# loop and process each packet recieved
while True:
    # more than max packet size, even if eth frames are much lower
    # tuple = (bytes, return address), pull raw data
    try:
        unprocessed_data, address = s.recvfrom(65565)
    except KeyboardInterrupt as error:
        sys.exit()

    # TODO - move to own function
    # 14 = dest mac (6), src mac (6), ethertype/len (2)
    frame_header_len = 14
    frame_header = struct.unpack("!6s6sH", unprocessed_data[:frame_header_len])
    src_mac, dest_mac, ethertype = frame_header

    # handle some nice formatting in the output plus descriptions
    ethertype_formatted = hex(ethertype)
    if ethertype in ETHERTYPES:
        ethertype_formatted = ethertype_formatted + ":" + ETHERTYPES[ethertype]

    print(f"| Frame > DestinationMAC=[{format_mac(dest_mac)}], ", 
          f"SourceMAC=[{format_mac(src_mac)}], ", 
          f"EtherType=[{ethertype_formatted}] |")
