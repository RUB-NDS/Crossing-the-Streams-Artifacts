"""AttackConfig + AlignmentMode.

The HTTP handler builds a final config by starting from an adapter's
default_config() and calling overlay() with the caller-supplied override
dict. Bytes fields (known_prefix, terminator, alphabet) arrive as strings
over JSON and are decoded here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Literal


class AlignmentMode(str, Enum):
    """How the engine picks the alignment length (Section 4.3).

    FULL_SWEEP tries every length in `alignment_lengths` per candidate;
    KNOWN_LENGTH pins the single length the attacker is assumed to know
    (the cost-easing assumption of Section 4.1).
    """

    FULL_SWEEP = "full_sweep"
    KNOWN_LENGTH = "known_length"


@dataclass
class AttackConfig:
    known_prefix: bytes
    alphabet: list[bytes]
    max_length: int
    terminator: bytes

    commit_margin: int
    max_rounds: int
    settle: float

    alignment_mode: AlignmentMode
    alignment_lengths: list[int]

    candidate_elimination: bool
    constant_prefix_trim: bool
    adaptive_alignment_sweep: bool
    alignment_reintroduction: bool
    alignment_carryover: bool

    outlier_threshold: int

    flush_bytes: int
    flush_pool: Literal["secrets_random", "high_ascii", "none"]
    measurement_min_segment_size: int

    candidate_fork_on_stall: bool = False
    fork_top_k: int = 5
    max_fork_depth: int = 2

    guess_prefill_bytes: int = 0

    expected: bytes | None = None

    label: str = ""

    def overlay(self, overrides: dict[str, Any]) -> AttackConfig:
        converted: dict[str, Any] = {}
        for key, value in overrides.items():
            if value is None:
                continue
            if key in ("known_prefix", "terminator", "expected"):
                converted[key] = value.encode("utf-8") if isinstance(value, str) else bytes(value)
            elif key == "alphabet":
                if isinstance(value, str):
                    converted[key] = [bytes([c]) for c in value.encode("utf-8")]
                else:
                    converted[key] = [bytes([c]) if isinstance(c, int) else bytes(c) for c in value]
            elif key == "alignment_mode":
                converted[key] = AlignmentMode(value) if isinstance(value, str) else value
            else:
                converted[key] = value
        return replace(self, **converted)
