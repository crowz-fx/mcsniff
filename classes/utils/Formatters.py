import re
from classes.constants.ColourChars import *


def format_mac(data: bytes) -> str:
    # 02 = pad with 0's till 2 chars, X = uppercase hex
    return ":".join(format(b, "02X") for b in data)


def format_ipv4(data: bytes) -> str:
    # d = decimal
    return ".".join(format(b, "d") for b in data)


def format_ipv6(data: bytes) -> str:
    # i know this is dodgy and i could have used a library, but where's the fun in that!

    # 02x = left pad with 0's until min len of 2, lower case letters
    initial_formatted = ":".join(format(b, "02x") for b in data)

    # very nasty way to process IPv6, truncating the largest :00 string to ::
    largest_00_str = {"start": -1, "length": 3}
    for match in re.compile(r"(:00)\1*").finditer(initial_formatted):
        # if the match is longer than the standard :00 AND any previous check, pull values
        if len(match.group()) > largest_00_str["length"]:
            largest_00_str["start"] = match.start()
            largest_00_str["length"] = len(match.group())

    second_formatted = initial_formatted
    # only if we did find a str of :00 larger than :00 i.e. :00:00
    # shove a _ so we can ignore it till the end when we turn it into ::
    if largest_00_str["length"] > 3:
        second_formatted = (
            initial_formatted[: largest_00_str["start"]]
            + "_"
            + initial_formatted[
                largest_00_str["start"] + largest_00_str["length"] + 1 :
            ]
        )

    # copy list so we can access index in it, can't modify second_formatted
    # as would screw index and throw 'No Such Index' errors
    formatted = list(second_formatted)
    for idx, i in enumerate(second_formatted):
        # check every 3rd char
        if idx % 2 == 0 and idx != 0:
            if i == ":" and second_formatted[idx - 1] != ":":
                formatted[idx] = ""

    # final replace if we did find a :00 long str to be replaced
    return "".join(formatted).replace("_", "::")


# TODO - fix as not a clean implementation
def format_payload(data: bytes) -> str:
    return "".join(chr(b) for b in data)


def print_green(output: str):
    print(GREEN, output, END, sep="")


def print_yellow(output: str):
    print(YELLOW, output, END, sep="")


def print_blue(output: str):
    print(BLUE, output, END, sep="")
