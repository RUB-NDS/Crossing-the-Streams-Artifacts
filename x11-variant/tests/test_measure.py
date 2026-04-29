import os
import tempfile
import unittest

from attacker.measure import DEFAULT_TX_BYTES_PATH, read_tx_bytes


class ReadTxBytesTests(unittest.TestCase):
    def test_reads_integer_from_path(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("12345\n")
            path = f.name
        try:
            self.assertEqual(read_tx_bytes(path), 12345)
        finally:
            os.unlink(path)

    def test_strips_whitespace(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("  9876543210  \n")
            path = f.name
        try:
            self.assertEqual(read_tx_bytes(path), 9876543210)
        finally:
            os.unlink(path)

    def test_default_path_constant(self):
        self.assertEqual(DEFAULT_TX_BYTES_PATH, "/sys/class/net/eth0/statistics/tx_bytes")

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            read_tx_bytes("/nonexistent/path/tx_bytes")


if __name__ == "__main__":
    unittest.main()
