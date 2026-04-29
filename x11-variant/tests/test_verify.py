import unittest

from attacker.verify import build_connection_setup


class BuildConnectionSetupTests(unittest.TestCase):
    def test_layout_is_48_bytes(self):
        cookie = bytes(range(16))
        setup = build_connection_setup(cookie)
        self.assertEqual(len(setup), 48)

    def test_first_byte_is_big_endian_marker(self):
        setup = build_connection_setup(bytes(16))
        self.assertEqual(setup[0:1], b"B")

    def test_protocol_version_11_0(self):
        setup = build_connection_setup(bytes(16))
        # bytes 2-5: major=0x000b minor=0x0000
        self.assertEqual(setup[2:6], b"\x00\x0b\x00\x00")

    def test_auth_name_is_mit_magic_cookie_1(self):
        setup = build_connection_setup(bytes(16))
        self.assertEqual(setup[12:30], b"MIT-MAGIC-COOKIE-1")

    def test_cookie_at_offset_32(self):
        cookie = bytes(range(16))
        setup = build_connection_setup(cookie)
        self.assertEqual(setup[32:48], cookie)

    def test_wrong_cookie_length_raises(self):
        with self.assertRaises(ValueError):
            build_connection_setup(b"")
        with self.assertRaises(ValueError):
            build_connection_setup(b"\x00" * 15)


if __name__ == "__main__":
    unittest.main()
