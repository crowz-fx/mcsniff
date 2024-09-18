from classes.constants.ColourChars import *


def format_mac(data):
    # 02 = pad with 0's till 2 chars, X = uppercase hex
    return ":".join(format(b, "02X") for b in data)


def format_ipv4(data):
    # d = decimal
    return ".".join(format(b, "d") for b in data)


def print_green(output):
    print(GREEN, output, END, sep="")


def print_yellow(output):
    print(YELLOW, output, END, sep="")


def print_blue(output):
    print(BLUE, output, END, sep="")
