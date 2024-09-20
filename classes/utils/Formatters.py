from classes.constants.ColourChars import *


def format_mac(data: bytes):
    # 02 = pad with 0's till 2 chars, X = uppercase hex
    return ":".join(format(b, "02X") for b in data)


def format_ipv4(data: bytes):
    # d = decimal
    return ".".join(format(b, "d") for b in data)


# TODO - fix as not a clean implementation
def format_payload(data: bytes):
    return "".join(chr(b) for b in data)


def print_green(output: str):
    print(GREEN, output, END, sep="")


def print_yellow(output: str):
    print(YELLOW, output, END, sep="")


def print_blue(output: str):
    print(BLUE, output, END, sep="")
