import unittest

from attacker.inject import ALIGNMENT_POOL, ANCHOR, build_probe


class BuildProbeTests(unittest.TestCase):
    def test_anchor_is_mit_magic_cookie_with_two_zero_pad(self):
        self.assertEqual(ANCHOR, b"MIT-MAGIC-COOKIE-1\x00\x00")
        self.assertEqual(len(ANCHOR), 20)

    def test_alignment_pool_is_high_bit_bytes(self):
        self.assertEqual(ALIGNMENT_POOL, bytes(range(0x80, 0x90)))
        self.assertEqual(len(ALIGNMENT_POOL), 16)

    def test_probe_layout_no_prefix_no_alignment(self):
        probe = build_probe(prefix=b"", candidate=b"\x42", align_len=0)
        self.assertEqual(probe, b"MIT-MAGIC-COOKIE-1\x00\x00\x42")

    def test_probe_layout_with_prefix_and_alignment(self):
        probe = build_probe(prefix=b"\x01\x02\x03", candidate=b"\x04", align_len=3)
        expected = b"MIT-MAGIC-COOKIE-1\x00\x00\x01\x02\x03\x04\x80\x81\x82"
        self.assertEqual(probe, expected)

    def test_probe_alignment_max(self):
        probe = build_probe(prefix=b"", candidate=b"\xff", align_len=7)
        self.assertEqual(probe, b"MIT-MAGIC-COOKIE-1\x00\x00\xff\x80\x81\x82\x83\x84\x85\x86")

    def test_align_len_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            build_probe(prefix=b"", candidate=b"\x00", align_len=8)
        with self.assertRaises(ValueError):
            build_probe(prefix=b"", candidate=b"\x00", align_len=-1)

    def test_candidate_must_be_one_byte(self):
        with self.assertRaises(ValueError):
            build_probe(prefix=b"", candidate=b"", align_len=0)
        with self.assertRaises(ValueError):
            build_probe(prefix=b"", candidate=b"\x00\x00", align_len=0)


if __name__ == "__main__":
    unittest.main()
