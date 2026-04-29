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


if __name__ == "__main__":
    unittest.main()
