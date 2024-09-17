# use the hex values like in the standard
# https://en.wikipedia.org/wiki/EtherType#Values
ETHER_TYPES = {
    # TODO - add in the rest
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
}

# produces a dict like { 'IPv4': 0x0800 ... }
ETHER_TYPES_REVERSED = dict(zip(ETHER_TYPES.values(), ETHER_TYPES.keys()))
