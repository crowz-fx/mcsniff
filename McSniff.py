"""

    McSniff - Lui Crowie, 2024

"""

import socket, sys

from classes.EthernetFrame import EthernetFrame
from classes.constants.EtherTypes import *
from classes.utils.Formatters import *

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
    # TODO - handle diff interfaces
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

    frame = EthernetFrame(unprocessed_data)
    print(frame)

    # check if it's a ETHER type we can process
    if frame.ETHER_TYPE in ETHER_TYPES:
      
      # IPv4
      if frame.ETHER_TYPE == ETHER_TYPES_REVERSED["IPv4"]:
        print_green(f"\\_ IPv4 > ")
