import unittest

from attacker.engine import locked


def make_samples(per_align_per_cand: dict) -> dict:
    """per_align_per_cand: {candidate_byte: [size_at_align_0, ..., size_at_align_7]}.
    Returns {bytes([cand]): [size, size, size, ...]} as the engine expects, where
    the list is the concatenation of all rounds' alignment results.
    """
    samples = {}
    for cand_byte, sizes in per_align_per_cand.items():
        if len(sizes) != 8:
            raise ValueError(f"need 8 alignments for {cand_byte:#04x}")
        samples[bytes([cand_byte])] = list(sizes)
    return samples


class LockedTests(unittest.TestCase):
    def test_clear_winner_locks(self):
        samples = make_samples({
            0x41: [100, 100, 100, 100, 100, 100, 100, 100],
            0x42: [120, 120, 120, 120, 120, 120, 120, 120],
            0x43: [125, 125, 125, 125, 125, 125, 125, 125],
        })
        ranked = sorted(samples, key=lambda c: _median(samples[c]))
        self.assertTrue(locked(ranked, samples, min_margin=8, min_agreement=5))
        self.assertEqual(ranked[0], b"\x41")

    def test_margin_too_small_does_not_lock(self):
        samples = make_samples({
            0x41: [100, 100, 100, 100, 100, 100, 100, 100],
            0x42: [104, 104, 104, 104, 104, 104, 104, 104],
        })
        ranked = sorted(samples, key=lambda c: _median(samples[c]))
        self.assertFalse(locked(ranked, samples, min_margin=8, min_agreement=5))

    def test_insufficient_agreement_does_not_lock(self):
        # Candidate 0x41 wins on alignments 0..3 and loses on 4..7
        samples = make_samples({
            0x41: [100, 100, 100, 100, 130, 130, 130, 130],
            0x42: [130, 130, 130, 130, 100, 100, 100, 100],
        })
        ranked = sorted(samples, key=lambda c: _median(samples[c]))
        self.assertFalse(locked(ranked, samples, min_margin=8, min_agreement=5))

    def test_agreement_threshold_exact(self):
        # Candidate 0x41 wins on alignments 0..4 (5 of 8) -> meets threshold
        samples = make_samples({
            0x41: [100, 100, 100, 100, 100, 130, 130, 130],
            0x42: [130, 130, 130, 130, 130, 100, 100, 100],
        })
        ranked = sorted(samples, key=lambda c: _median(samples[c]))
        # Median for 0x41 is 100; for 0x42 is 115; margin = 15 >= 8 ✓.
        # Per-alignment: 0x41 wins 5/8 ✓.
        self.assertTrue(locked(ranked, samples, min_margin=8, min_agreement=5))

    def test_multi_round_samples_stack(self):
        samples = make_samples({
            0x41: [100, 100, 100, 100, 100, 100, 100, 100],
            0x42: [120, 120, 120, 120, 120, 120, 120, 120],
        })
        # Add a second round
        samples[b"\x41"].extend([100] * 8)
        samples[b"\x42"].extend([120] * 8)
        ranked = sorted(samples, key=lambda c: _median(samples[c]))
        self.assertTrue(locked(ranked, samples, min_margin=8, min_agreement=5))


def _median(values):
    import statistics
    return statistics.median(values)


class SyntheticOracle:
    """Returns a small size when (prefix + candidate) is a prefix of the
    target cookie at this byte position; a larger size otherwise."""

    def __init__(self, cookie: bytes):
        self.cookie = cookie

    async def __call__(self, prefix: bytes, candidate: bytes, align_len: int) -> int:
        n = len(prefix) + len(candidate)
        if self.cookie[: n] == prefix + candidate:
            return 100
        return 120


class FindNextByteTests(unittest.IsolatedAsyncioTestCase):
    async def test_recovers_first_byte_of_cookie(self):
        from attacker.engine import find_next_byte
        cookie = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
        oracle = SyntheticOracle(cookie)
        winner = await find_next_byte(
            oracle=oracle,
            prefix=b"",
            byte_index=0,
            min_margin=8,
            min_agreement=5,
            max_rounds=4,
        )
        self.assertEqual(winner, b"\xa1")

    async def test_recovers_byte_after_correct_prefix(self):
        from attacker.engine import find_next_byte
        cookie = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
        oracle = SyntheticOracle(cookie)
        winner = await find_next_byte(
            oracle=oracle,
            prefix=cookie[:5],
            byte_index=5,
            min_margin=8,
            min_agreement=5,
            max_rounds=4,
        )
        self.assertEqual(winner, bytes([cookie[5]]))

    async def test_raises_when_oracle_signal_too_weak(self):
        from attacker.engine import find_next_byte, RecoveryFailed

        class FlatOracle:
            async def __call__(self, prefix, candidate, align_len):
                return 100  # all candidates indistinguishable

        with self.assertRaises(RecoveryFailed):
            await find_next_byte(
                oracle=FlatOracle(),
                prefix=b"",
                byte_index=0,
                min_margin=8,
                min_agreement=5,
                max_rounds=2,
            )


if __name__ == "__main__":
    unittest.main()
