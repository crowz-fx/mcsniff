# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages

CONTROL_MESSAGES = {
    0: {"value": "Echo Reply"},
    3: {
        "value": "Destination Unreachable",
        "codes": {
            0: "Destination network unreachable",
            1: "Destination host unreachable",
            2: "Destination protocol unreachable",
            3: "Destination port unreachable",
            4: "Fragmentation required, and DF flag set",
            5: "Source route failed",
            6: "Destination network unknown",
            7: "Destination host unknown",
            8: "Source host isolated",
            9: "Network administratively prohibited",
            10: "Host administratively prohibited",
            11: "Network unreachable for ToS",
            12: "Host unreachable for ToS",
            13: "Communication administratively prohibited",
            14: "Host Precedence Violation",
            15: "Precedence cutoff in effect",
        },
    },
    5: {
        "value": "Redirect Message",
        "codes": {
            0: "Redirect Datagram for the Network",
            1: "Redirect Datagram for the Host",
            2: "Redirect Datagram for the ToS & network",
            3: "Redirect Datagram for the ToS & host",
        },
    },
    8: {"value": "Echo Request"},
    9: {"value": "Router Advertistment"},
    10: {"value": "Router Solicitation"},
    11: {
        "value": "Time Exceeded",
        "codes": {0: "TTL expired in transit", 1: "Fragment reassembly time exceeded"},
    },
    12: {
        "value": "Param Problem: Bad IP Header",
        "codes": {
            0: "Pointer indicates the error",
            1: "Missing a required option",
            2: "Bad length",
        },
    },
    13: {"value": "Timestamp"},
    14: {"value": "Timestamp Reply"},
    42: {"value": "Extended Echo Request"},
    43: {"value": "Extended Echo Reply"},
}
