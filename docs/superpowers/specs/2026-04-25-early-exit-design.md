# Early-exit on wrong commit — design

## Motivation

`scripts/sweep_min_margin.sh` walks `min_margin` from 8 to 128 in steps of
8 across multiple `(variant, scenario)` pairs. For each `min_margin` it
runs `benchmark.py` with `--trials N`. When the chosen `min_margin` is
too low for the stack to converge cleanly, *every* trial in that run
spends its full attack budget chasing a wrong commit before failing —
which can stretch a single doomed sweep step from minutes into the
tens-of-minutes range.

Most of that work is wasted. The benchmark already knows the password
it asked the client to set, so it can tell the attacker exactly what the
correct sequence of commits should be. As soon as the engine commits a
byte that doesn't match, the sweep can abandon that `min_margin` and
move on.

## Goals

1. Let the engine detect a wrong commit and abort cheaply when given a
   ground-truth `expected` string.
2. Make `benchmark.py --early-exit` populate `expected` for every trial
   and abort the entire run on the first mismatch (or on a hard `/cancel`
   from another stack), still emitting a partial JSON+CSV with a
   top-level `success: false`.
3. Wire `EARLY_EXIT=1` into `sweep_min_margin.sh` as the default so the
   sweep gets the speed-up automatically.
4. Keep `verify_*.py` honest — they intentionally don't pass `expected`,
   so they continue running attacks to completion as the end-to-end
   smoke test.

## Non-goals

- Cancelling an in-flight `/run_attack` at the urllib socket level. Hard
  cancel is implemented server-side via a new `/cancel` endpoint that
  flips an `asyncio.Event` the engine consumes between positions; this
  trades sub-second cancellation for ~one-position latency in exchange
  for a far simpler implementation.
- Changing the existing `verify_*.py` smoke flow.
- Changing the existing per-trial JSON shape beyond two new optional
  fields on the engine response.

---

## Engine changes (`attacker/attack/engine.py`, `attacker/attack/config.py`)

### 1. New optional config field

Add to `AttackConfig`:

```python
expected: bytes | None = None
```

`AttackConfig.overlay()` already centralises bytes marshalling for the
`known_prefix` / `terminator` fields; extend the same `str → bytes`
decoding to `expected` so the HTTP layer can forward it as a JSON
string.

### 2. Mismatch check in the position loop

In `run_attack()`, after each `committed` position is appended to
`per_position` and *before* the existing terminator/recovered handling,
introduce the mismatch check:

```python
for pr in committed:
    best_byte = pr["best"].encode("latin-1")
    per_position.append(pr)
    if pr["successful_alignment"] is not None:
        prev_nl = pr["successful_alignment"]

    n = pr["position"]
    if config.expected is not None and n < len(config.expected):
        if best_byte != config.expected[n:n+1]:
            pr["mismatch"] = True
            pr["expected_byte"] = config.expected[n:n+1].decode("latin-1")
            pr["committed_byte"] = pr["best"]
            aborted = True
            abort_reason = "mismatch"
            done = True
            break

    if best_byte == config.terminator:
        done = True
        break
    recovered += best_byte
```

The mismatch comparison happens *before* the terminator match, so a
wrong byte committed at the terminator position is treated as a
mismatch (not as a clean end-of-attack).

The check fires only at the engine's outer commit step — never inside
`crack_byte_position` or `resolve_stalled_position`. Speculative bytes
explored by fork-on-stall are not subject to abort until they're
actually committed back to the outer loop.

### 3. Cancellation event

`run_attack()` accepts an optional `cancel_event: asyncio.Event | None
= None`. At the top of each outer position iteration:

```python
if cancel_event is not None and cancel_event.is_set():
    aborted = True
    abort_reason = "cancelled"
    break
```

### 4. Augmented return shape

The existing keys are preserved. Two new keys are appended:

```python
return {
    "recovered": recovered.decode("latin-1"),
    "elapsed_seconds": elapsed,
    "total_guesses": sum(p["guesses"] for p in per_position),
    "per_position": per_position,
    "config_label": config.label,
    "aborted": aborted,         # default False
    "abort_reason": abort_reason, # "mismatch" | "cancelled" | None
}
```

Per-position dicts gain `mismatch`, `expected_byte`, `committed_byte`
fields *only* on the position that triggered the abort. Callers that
ignore them are unaffected.

---

## HTTP plumbing (`attacker/mitm.py`)

### 1. `/run_attack` accepts `expected`

The endpoint body becomes:

```json
{
  "variant": "direct|beast|ansible",
  "config":  { ... existing overlay ... },
  "expected": "hunter2\r"   // optional
}
```

`handle_run_attack` injects `expected` into the overlay dict before
calling `AttackConfig.overlay()`, so the engine sees it through the
existing config path. No new positional argument on `run_unified_attack`
is needed beyond the cancel event.

### 2. Module-scoped cancel event

Add at module scope:

```python
_CANCEL_EVENT = asyncio.Event()
```

`handle_run_attack` clears it on entry (after acquiring `_ATTACK_LOCK`)
and passes it as `cancel_event` to `run_unified_attack`.

### 3. `POST /cancel` endpoint

```python
async def handle_cancel(request: web.Request) -> web.Response:
    if _ATTACK_LOCK.locked():
        _CANCEL_EVENT.set()
        return web.json_response({"ok": True, "cancelled": True})
    return web.json_response({"ok": True, "cancelled": False})
```

Registered alongside the other routes in `mitm.py`. Idempotent — calling
`/cancel` when no attack is running returns `cancelled: False` and is a
no-op.

---

## Benchmark changes (`scripts/benchmark.py`)

### 1. New CLI flag

```python
ap.add_argument("--early-exit", action="store_true",
                help="abort the run on the first wrong commit; populates "
                     "the engine's `expected` parameter from the known "
                     "password and broadcasts /cancel to all stacks on "
                     "failure")
```

### 2. Phase-aware `expected` construction

`run_variant()` already knows the password and the per-variant
terminators. Extend `_run_two_phase` to accept two new optional
parameters:

```python
expected_phase1: str | None = None
expected_phase2: str | None = None
```

When non-`None`, each is passed through to `_http_run_attack` as the
top-level `expected` field.

`run_variant()` builds them when `--early-exit` is on:

| variant | phase1 expected                | phase2 expected            |
|---------|--------------------------------|----------------------------|
| direct  | `str(len(password)) + "\r"`    | `password + "\r"`          |
| beast   | `str(len(password)) + "\r"`    | `password + "\r"`          |
| ansible | `chr(len(password)) + "\x00"`  | `password + "\n"`          |

Direct and beast encode the length as decimal ASCII (RESP `$<len>\r\n`
framing), so phase1 expected is the ASCII string `"8"` for an 8-char
password. Ansible encodes the length as a single-byte SSH-channel-data
length value — phase1's alphabet is bytes `\x01`–`\x20` — so phase1
expected is `chr(8) + "\x00"` = `"\x08\x00"`. JSON serialisation of
control bytes round-trips correctly through `json.dumps` / `UTF-8
decode` in `overlay()`.

### 3. Shared abort state

Top-level main thread holds:

- `stop_event: threading.Event` — set on first failure (under
  `--early-exit`).
- `attacker_bases: list[str]` — populated by each worker as it
  computes its attacker URL via `inspect_ip()`. Protected by
  `results_lock`.

A small helper:

```python
def _broadcast_cancel(bases: list[str]) -> None:
    for base in bases:
        try:
            http(f"{base}/cancel", method="POST", body={}, timeout=5)
        except Exception:
            pass  # best-effort; the worker will time out naturally
```

### 4. Worker behaviour

Before each trial:

```python
if early_exit and stop_event.is_set():
    break
```

After each trial — when `early_exit` is on and the trial failed
(`ok == False`, including `aborted == True` from the engine):

```python
with results_lock:
    if not stop_event.is_set():
        stop_event.set()
        bases_snapshot = list(attacker_bases)
_broadcast_cancel(bases_snapshot)
```

Cancelled trials (those whose `/run_attack` returned with
`aborted: True, abort_reason: "cancelled"`) are recorded with
`ok=False, status="cancelled"` and the worker exits its loop. They are
*not* treated as the originating failure — only the first stack to
detect a mismatch sets `stop_event` and broadcasts.

### 5. Output additions

`benchmark_results.json` gets two new top-level keys:

```json
{
  "config":   {...},
  "passwords": [...],
  "results":  [...],
  "summary":  {...},
  "wall_seconds": 12.3,
  "early_exit_triggered": true,
  "success":  false
}
```

`success` is `True` iff `not failures and stop_event_never_set and all
trials passed`.

`benchmark_summary.csv` gets one new column appended at the end of each
row: `early_exit_triggered` (`true` / `false`).

Exit code:

- Without `--early-exit`: unchanged. Exit `0` iff all trials passed and
  no setup failures; else `1`.
- With `--early-exit`: same logic, but a triggered abort guarantees
  exit `1`.

---

## Sweep script (`scripts/sweep_min_margin.sh`)

Add an env var:

```bash
EARLY_EXIT="${EARLY_EXIT:-1}"
```

In the inner `python3 scripts/benchmark.py …` invocation, append
`--early-exit` when `EARLY_EXIT=1` (the default). Setting `EARLY_EXIT=0`
restores the old "run every trial" behaviour for parity sweeps.

The existing "non-zero exit → bump `mm` and retry" loop is untouched —
`--early-exit` only changes how *fast* a failed `mm` exits.

Header comments updated to mention the new default.

---

## Verify scripts

`scripts/verify_{direct,beast,ansible}.py`: **no changes**. They build
`/run_attack` request bodies directly, never include `expected`, and so
continue running attacks to completion regardless of intermediate
commits. This is intentional — verify scripts are the end-to-end smoke
check; if they pass without `expected`, the attack genuinely worked.

---

## Tests

Add a host-side test in `attacker/attack/tests/` that uses a fake
adapter to drive `run_attack()` deterministically:

1. **`test_engine_expected_match`** — fake adapter scripted so committed
   bytes match `expected = b"abc\r"`. Assert `aborted is False`,
   `abort_reason is None`, `recovered == "abc"`, terminator handling
   unchanged.
2. **`test_engine_expected_mismatch`** — fake adapter scripted so the
   commit at position 1 is wrong (e.g. expected `b"abc\r"`, commits
   `b"axc\r"`). Assert `aborted is True`, `abort_reason == "mismatch"`,
   `per_position[1]["mismatch"] is True`, `per_position[1]["expected_byte"]
   == "b"`, `per_position[1]["committed_byte"] == "x"`, no further
   positions appended.
3. **`test_engine_expected_terminator_mismatch`** — same fake adapter but
   the wrong commit is at the terminator position (expects `b"\r"`,
   commits a non-terminator byte). Assert `aborted is True,
   abort_reason == "mismatch"`. This proves the mismatch check fires
   before the terminator-done check.

Cancellation is exercised at the integration level only (via the
benchmark + `/cancel` flow under a multi-stack run); a unit test for the
event hook would just be reading a flag.

---

## File map

- `attacker/attack/config.py` — add `expected: bytes | None = None`,
  extend `overlay()` decoding.
- `attacker/attack/engine.py` — add `cancel_event` parameter; mismatch
  check in commit loop; augment return dict with `aborted` /
  `abort_reason`.
- `attacker/mitm.py` — `/run_attack` accepts top-level `expected`;
  module-scoped `_CANCEL_EVENT`; new `/cancel` route.
- `scripts/benchmark.py` — `--early-exit` flag; phase1/phase2 expected
  construction in `run_variant()`; shared `stop_event` and
  `attacker_bases`; `_broadcast_cancel()`; new top-level JSON / CSV
  fields.
- `scripts/sweep_min_margin.sh` — `EARLY_EXIT=1` default, conditional
  `--early-exit` append.
- `attacker/attack/tests/test_engine_expected.py` — three new fake-
  adapter tests.

---

## Risks and trade-offs

- **Server-side cancel latency.** A stuck position can hold the lock for
  seconds before the cancel event is observed. Acceptable: the goal is
  abort-the-sweep-step, not abort-this-millisecond.
- **`expected` exposes ground truth to the engine.** Only relevant in
  benchmark/sweep paths where the benchmark already controls the
  password. `verify_*.py` pointedly does not pass it, so the smoke
  signal stays honest.
- **Terminator-aware expected** means each variant's caller has to
  build the right byte. Centralised in `run_variant()` so there's a
  single source of truth.
