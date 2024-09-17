"""

    McSniff - Lui Crowie, 2024

"""

import socket, sys
import struct

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
    unprocessed_data, address = s.recvfrom(65565)

    # 14 = dest mac (6), src mac (6), ethertype/len (2)
    frame_header_len = 14
    frame_header = struct.unpack("!6s6s2s", unprocessed_data[:frame_header_len])
    
    print(frame_header)

    src_mac, dest_mac, ethertype = frame_header

    print(src_mac, dest_mac, ethertype)

