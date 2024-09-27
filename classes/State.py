from classes.constants.EtherTypes import ETHER_TYPES_REVERSED
from classes.constants.IPProtocols import IP_PROTOCOLS_REVERSED

# default options if nothing supplied
OPTIONS = {
    "interface": "eth0",
    "payload": False,
    "statistics": False,
    "https": False,
    "level2": ["ETH", "ARP", "RARP"],
    "level3": ["IPv4", "IPv6", "ICMP", "ICMPv6", "IGMP"],
    "level4": ["TCP", "UDP"],
}

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


def update_stats(key: str, value: any = 1):
    # for counts, append
    if type(value) is int:
        STAT_COUNTS[key] += value

    # for timestamps/time set new value
    if type(value) is str:
        STAT_COUNTS[key] = value
