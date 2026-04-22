"""AttackConfig + AlignmentMode.

The HTTP handler builds a final config by starting from an adapter's
default_config() and calling overlay() with the caller-supplied override
dict. Bytes fields (known_prefix, terminator, alphabet) arrive as strings
over JSON and are decoded here, centralising the marshalling.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Literal


class AlignmentMode(str, Enum):
    FULL_SWEEP = "full_sweep"
    FIXED_SINGLE = "fixed_single"


@dataclass
class AttackConfig:
    known_prefix: bytes
    alphabet: list[bytes]
    max_length: int
    terminator: bytes

    min_margin: int
    max_rounds: int
    settle: float

    alignment_mode: AlignmentMode
    alignment_lengths: list[int]

    candidate_elimination: bool
    constant_prefix_trim: bool
    adaptive_alignment: bool
    stall_detection: bool
    alignment_hint_carryover: bool

    outlier_threshold: int

    flush_bytes: int
    flush_pool: Literal["secrets_random", "high_ascii", "none"]
    measurement_min_segment_size: int

    candidate_fork_on_stall: bool = True
    fork_top_k: int = 5
    max_fork_depth: int = 2

    label: str = ""

    def overlay(self, overrides: dict[str, Any]) -> "AttackConfig":
        """Return a new config with `overrides` applied; bytes fields decoded."""
        converted: dict[str, Any] = {}
        for key, value in overrides.items():
            if value is None:
                continue
            if key in ("known_prefix", "terminator"):
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
