import struct

from classes.State import OPTIONS
from classes.constants.ColourChars import BLUE, END, GREEN, YELLOW


HEX_DUMP_BYTES_PER_LINE = 16


def format_mac(data: bytes) -> str:
    # 02 = pad with 0's till 2 chars, X = uppercase hex
    return ":".join(format(b, "02X") for b in data)


def format_ipv4(data: bytes) -> str:
    # d = decimal
    return ".".join(format(b, "d") for b in data)


# i know this is dodgy and i could have used a library, but where's the fun in that!
def format_ipv6(data: bytes) -> str:

    # 8 groups of 16 bits, x = lower case hex with no leading 0's (RFC 5952)
    groups = [format(group, "x") for group in struct.unpack("!8H", data)]

    # only a run of 2+ zero groups gets shortened to ::, a lone 0 group stays as is
    zero_run_start, zero_run_len = find_longest_zero_run(groups)
    if zero_run_len < 2:
        return ":".join(groups)

    before_run = ":".join(groups[:zero_run_start])
    after_run = ":".join(groups[zero_run_start + zero_run_len :])
    return before_run + "::" + after_run


def find_longest_zero_run(groups: list[str]) -> tuple[int, int]:
    # returns (start index, length), on a tie the first run wins as per RFC 5952
    longest_start, longest_len = -1, 0
    current_start, current_len = 0, 0

    for idx, group in enumerate(groups):
        if group != "0":
            current_len = 0
            continue

        if current_len == 0:
            current_start = idx
        current_len += 1

        if current_len > longest_len:
            longest_start, longest_len = current_start, current_len

    return longest_start, longest_len


# anything outside this range becomes '.' so payload bytes dont mess with the terminal
def is_printable_ascii(byte: int) -> bool:
    return 0x20 <= byte <= 0x7E


# newline/tab kept on top of printable ASCII so text protocols like HTTP stay readable
def format_payload(data: bytes) -> str:
    return "".join(
        chr(b) if is_printable_ascii(b) or b in (0x0A, 0x09) else "." for b in data
    )


# xxd style, offset | 16 bytes of hex split 8+8 | ascii, newline/tab are
# not kept in the ascii column so every line stays the same width
def format_hex_dump(data: bytes) -> str:
    lines = []

    for offset in range(0, len(data), HEX_DUMP_BYTES_PER_LINE):
        chunk = data[offset : offset + HEX_DUMP_BYTES_PER_LINE]

        hex_bytes = [format(b, "02x") for b in chunk]
        # pad a short last line so its ascii column lines up with the ones above
        hex_bytes += ["  "] * (HEX_DUMP_BYTES_PER_LINE - len(chunk))
        hex_column = " ".join(hex_bytes[:8]) + "  " + " ".join(hex_bytes[8:])

        ascii_column = "".join(chr(b) if is_printable_ascii(b) else "." for b in chunk)

        lines.append(f"{offset:04x}  {hex_column}  |{ascii_column}|")

    return "\n".join(lines)


def print_payload(data: bytes):
    formatted = format_hex_dump(data) if OPTIONS["hex"] else format_payload(data)

    print_blue("|___PAYLOAD")
    print_blue("       -------")
    print_blue(formatted)
    print_blue("       -------")


def print_green(output: str):
    print(GREEN, output, END, sep="")


def print_yellow(output: str):
    print(YELLOW, output, END, sep="")


def print_blue(output: str):
    print(BLUE, output, END, sep="")
