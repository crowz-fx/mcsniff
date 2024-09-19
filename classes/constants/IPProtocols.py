# use the hex values like in the standard
# https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
IP_PROTOCOLS = {
    0x01: "ICMP",
    0x04: "IPv4",
    0x06: "TCP",
    0x11: "UDP",
    0x29: "IPv6",
    0x3A: "ICMPv6",
}

# produces a dict like { 'IPv4': 0x04 ... }
IP_PROTOCOLS_REVERSED = dict(zip(IP_PROTOCOLS.values(), IP_PROTOCOLS.keys()))
