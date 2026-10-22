import unittest

from classes.utils.Formatters import format_hex_dump


class TestFormatHexDump(unittest.TestCase):
    def test_full_line_has_offset_split_hex_and_ascii(self):
        output = format_hex_dump(b"GET / HTTP/1.1\r\n")

        self.assertEqual(
            output,
            "0000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|",
        )

    def test_offsets_count_up_in_hex_per_line(self):
        lines = format_hex_dump(bytes(40)).split("\n")

        self.assertEqual([line[:4] for line in lines], ["0000", "0010", "0020"])

    def test_short_last_line_ascii_column_lines_up_with_full_line(self):
        full_line, short_line = format_hex_dump(b"A" * 16 + b"B" * 3).split("\n")

        self.assertEqual(full_line.index("|"), short_line.index("|"))
        self.assertTrue(short_line.endswith("|BBB|"))

    def test_exactly_one_line_of_bytes_has_no_extra_line(self):
        self.assertEqual(len(format_hex_dump(bytes(16)).split("\n")), 1)

    def test_non_printable_bytes_including_newline_and_tab_are_dots(self):
        output = format_hex_dump(b"\x1b\n\t\x9b\x00a")

        self.assertTrue(output.endswith("|....." + "a|"))
        self.assertNotIn("\x1b", output)

    def test_empty_data_is_empty_string(self):
        self.assertEqual(format_hex_dump(b""), "")


if __name__ == "__main__":
    unittest.main()
