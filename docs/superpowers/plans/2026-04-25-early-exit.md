# Early-exit on wrong commit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the attacker engine abort fast when a known-wrong byte commits (driven by the benchmark's ground-truth password), and let the benchmark abort the entire run + cancel sibling stacks on the first such failure.

**Architecture:** The engine gains an optional `expected: bytes` config field. After each commit, a pure helper `_check_expected_match` compares the committed byte to `expected[N]`; on mismatch the engine returns early with `aborted=True, abort_reason="mismatch"`. A second abort path — `cancel_event: asyncio.Event` checked between positions — gives `mitm.py`'s new `POST /cancel` endpoint a way to short-circuit a running attack on demand. `benchmark.py --early-exit` populates `expected` per phase, and on the first trial failure it sets a shared `threading.Event`, broadcasts `/cancel` to every stack's attacker, and emits a partial JSON+CSV with `success: false`. `sweep_min_margin.sh` adds `EARLY_EXIT=1` (default on) so the sweep gets the speed-up automatically.

**Tech Stack:** Python (asyncio, aiohttp on the attacker container; stdlib-only on host scripts), bash, Docker compose.

**Spec:** `docs/superpowers/specs/2026-04-25-early-exit-design.md`

---

## File map

- **Create:** `attacker/attack/tests/test_engine_expected.py` — unit tests for the mismatch helper.
- **Modify:** `attacker/attack/config.py` — add `expected: bytes | None = None` and extend `overlay()` decoding.
- **Modify:** `attacker/attack/tests/test_config.py` — fix stale `candidate_fork_on_stall` default assertion; add overlay-roundtrip test for `expected`.
- **Modify:** `attacker/attack/engine.py` — add `_check_expected_match` helper; mismatch + cancel paths in `run_attack`; new `aborted` / `abort_reason` return fields.
- **Modify:** `attacker/mitm.py` — `/run_attack` accepts top-level `expected`; module-scoped `_CANCEL_EVENT`; new `POST /cancel` route; pass `cancel_event` into the engine.
- **Modify:** `scripts/benchmark.py` — `--early-exit` CLI; per-variant phase1/phase2 `expected`; cross-stack stop event + `_broadcast_cancel`; new top-level JSON + CSV fields.
- **Modify:** `scripts/sweep_min_margin.sh` — `EARLY_EXIT=1` default; conditional `--early-exit` append.

Tests live alongside the modules they exercise (`attacker/attack/tests/`). The benchmark, sweep, mitm.py, and adapter wiring are validated by an integration smoke at the end of the plan, not unit tests — `aiohttp` isn't installed on host so we can't unit-test the engine end-to-end without standing up the container.

---

### Task 0: Fix stale `test_config` assertion (prep)

After commit `63fd9ec` flipped `candidate_fork_on_stall` to default-`False`, `test_config.py:test_fork_fields_default_on_and_tuned` was left asserting `True`. We need a green host-side baseline before adding new tests.

**Files:**
- Modify: `attacker/attack/tests/test_config.py:64-68`

- [ ] **Step 1: Run the test to see the current failure.**

```bash
python -m attacker.attack.tests.test_config
```

Expected: `AssertionError` on `assert cfg.candidate_fork_on_stall is True`.

- [ ] **Step 2: Update the assertion to match the current default.**

Replace lines 64-68:

```python
def test_fork_fields_default_on_and_tuned():
    cfg = AttackConfig(**_base_kwargs())
    assert cfg.candidate_fork_on_stall is False
    assert cfg.fork_top_k == 5
    assert cfg.max_fork_depth == 2
```

(Function name kept for git-blame continuity; the docstring/values now reflect the *off-by-default* state.)

- [ ] **Step 3: Run the test to verify it passes.**

```bash
python -m attacker.attack.tests.test_config
```

Expected: `config tests: ok`.

- [ ] **Step 4: Commit.**

```bash
git add attacker/attack/tests/test_config.py
git commit -m "fix(tests): Sync candidate_fork_on_stall default assertion to False"
```

---

### Task 1: Add `expected` field to `AttackConfig` + overlay decoding

The engine reads its ground-truth from `config.expected`. The HTTP layer ships it as a JSON string, so `overlay()` needs to decode `str → bytes` for it (same path as `known_prefix` and `terminator`).

**Files:**
- Modify: `attacker/attack/config.py`
- Modify: `attacker/attack/tests/test_config.py`

- [ ] **Step 1: Write the failing test.**

Append to `test_config.py` (above the `if __name__ == "__main__":` block):

```python
def test_expected_defaults_to_none():
    cfg = AttackConfig(**_base_kwargs())
    assert cfg.expected is None


def test_overlay_decodes_expected_from_str():
    base = AttackConfig(**_base_kwargs())
    overridden = base.overlay({"expected": "hunter2\r"})
    assert overridden.expected == b"hunter2\r"


def test_overlay_decodes_expected_with_control_bytes():
    # Ansible phase1 expected uses chr(len) + "\x00" — round-trip must preserve
    # control bytes exactly.
    base = AttackConfig(**_base_kwargs())
    overridden = base.overlay({"expected": "\x08\x00"})
    assert overridden.expected == b"\x08\x00"


def test_overlay_expected_none_keeps_field_unset():
    base = AttackConfig(**_base_kwargs())
    # The overlay is meant to skip None values, matching the existing pattern.
    overridden = base.overlay({"expected": None})
    assert overridden.expected is None
```

Add the new tests to the `__main__` block as well:

```python
if __name__ == "__main__":
    test_construct_defaults()
    test_from_dict_partial_override()
    test_overlay_handles_bytes_fields_as_str()
    test_fork_fields_default_on_and_tuned()
    test_overlay_fork_fields()
    test_expected_defaults_to_none()
    test_overlay_decodes_expected_from_str()
    test_overlay_decodes_expected_with_control_bytes()
    test_overlay_expected_none_keeps_field_unset()
    print("config tests: ok")
```

- [ ] **Step 2: Run the test, verify it fails.**

```bash
python -m attacker.attack.tests.test_config
```

Expected: `AttributeError: 'AttackConfig' object has no attribute 'expected'` (the new tests reference an unknown field).

- [ ] **Step 3: Add the field to `AttackConfig`.**

In `attacker/attack/config.py`, between `guess_prefill_bytes` and `label`:

```python
    guess_prefill_bytes: int = 0

    expected: bytes | None = None

    label: str = ""
```

- [ ] **Step 4: Extend `overlay()` to decode `expected` as bytes.**

In `attacker/attack/config.py`, modify the `if key in ("known_prefix", "terminator"):` branch in `overlay()`:

```python
            if key in ("known_prefix", "terminator", "expected"):
                converted[key] = value.encode("utf-8") if isinstance(value, str) else bytes(value)
```

- [ ] **Step 5: Run the tests, verify they pass.**

```bash
python -m attacker.attack.tests.test_config
```

Expected: `config tests: ok`.

- [ ] **Step 6: Commit.**

```bash
git add attacker/attack/config.py attacker/attack/tests/test_config.py
git commit -m "feat(config): Add optional expected field with bytes-decoding overlay"
```

---

### Task 2: Add `_check_expected_match` helper to engine.py

A pure function that decides whether a committed byte is a mismatch given the expected stream. Pulled out so we can unit-test it without aiohttp (the engine's `run_attack` imports aiohttp eagerly, which isn't available on the host).

**Files:**
- Create: `attacker/attack/tests/test_engine_expected.py`
- Modify: `attacker/attack/engine.py`

- [ ] **Step 1: Write the failing tests.**

Create `attacker/attack/tests/test_engine_expected.py`:

```python
"""Tests for the expected-mismatch helper.

Run: python -m attacker.attack.tests.test_engine_expected
"""
from attacker.attack.engine import _check_expected_match


def test_expected_none_returns_none():
    assert _check_expected_match(b"a", 0, None) is None


def test_position_past_expected_returns_none():
    # Once the engine commits past len(expected) we don't second-guess —
    # this is normal terminator handling territory.
    assert _check_expected_match(b"x", 5, b"abc") is None


def test_matching_byte_returns_none():
    assert _check_expected_match(b"b", 1, b"abc") is None


def test_mismatching_byte_returns_dict():
    info = _check_expected_match(b"x", 1, b"abc")
    assert info == {"expected_byte": "b", "committed_byte": "x"}


def test_mismatch_at_terminator_position_is_detected():
    # Position 3 of "abc\r" is the terminator. Committing the wrong byte
    # there must still register as a mismatch — the engine relies on this
    # to catch terminator-position commit errors.
    info = _check_expected_match(b"\n", 3, b"abc\r")
    assert info == {"expected_byte": "\r", "committed_byte": "\n"}


def test_mismatch_with_control_bytes():
    # Ansible phase1 uses chr(len) — make sure non-printable bytes work.
    info = _check_expected_match(b"\x09", 0, b"\x08\x00")
    assert info == {"expected_byte": "\x08", "committed_byte": "\x09"}


if __name__ == "__main__":
    test_expected_none_returns_none()
    test_position_past_expected_returns_none()
    test_matching_byte_returns_none()
    test_mismatching_byte_returns_dict()
    test_mismatch_at_terminator_position_is_detected()
    test_mismatch_with_control_bytes()
    print("engine-expected tests: ok")
```

- [ ] **Step 2: Run the tests, verify they fail.**

```bash
python -m attacker.attack.tests.test_engine_expected
```

Expected: `ImportError: cannot import name '_check_expected_match' from 'attacker.attack.engine'`.

- [ ] **Step 3: Add the helper to `engine.py`.**

Insert after the `_pick_alignment_with_largest_gap` function (~line 50, before `_select_initial_alignment`):

```python
def _check_expected_match(
    committed_byte: bytes,
    position: int,
    expected: bytes | None,
) -> dict | None:
    """Compare a committed byte against the ground-truth `expected` stream.

    Returns None when there's nothing to check (no expected provided, or
    we've committed past the end of expected — the engine's normal
    terminator path handles end-of-attack on its own). Returns a dict
    describing the mismatch otherwise; callers should attach the dict
    fields to the per-position record and trigger an early abort.
    """
    if expected is None or position >= len(expected):
        return None
    expected_byte = expected[position : position + 1]
    if committed_byte == expected_byte:
        return None
    return {
        "expected_byte": expected_byte.decode("latin-1"),
        "committed_byte": committed_byte.decode("latin-1"),
    }
```

- [ ] **Step 4: Run the tests, verify they pass.**

```bash
python -m attacker.attack.tests.test_engine_expected
```

Expected: `engine-expected tests: ok`.

- [ ] **Step 5: Commit.**

```bash
git add attacker/attack/engine.py attacker/attack/tests/test_engine_expected.py
git commit -m "feat(engine): Add _check_expected_match helper for ground-truth abort"
```

---

### Task 3: Wire mismatch helper into `run_attack` commit loop

Hook the helper into the engine's outer "commit a result" loop. On mismatch, attach the info to the position dict, set `aborted=True, abort_reason="mismatch"`, and break out. The terminator check already in the loop runs *after* the mismatch check so that a wrong commit at the terminator position is still flagged.

**Files:**
- Modify: `attacker/attack/engine.py:565-665`

This is wired by integration; `run_attack` imports aiohttp so we can't unit-test it on host. The benchmark E2E in Task 11 validates the wiring.

- [ ] **Step 1: Add the abort-state initialisation in `run_attack`.**

In `attacker/attack/engine.py`, inside `run_attack()` near the other locals (around line 595, just after `recovered = b""`):

```python
            recovered = b""
            per_position: list[dict[str, Any]] = []
            prev_nl: int | None = None
            aborted = False
            abort_reason: str | None = None
```

- [ ] **Step 2: Wire the mismatch check into the commit loop.**

Replace the inner `for pr in committed:` block (currently around lines 636-648) with:

```python
                for pr in committed:
                    best_byte = pr["best"].encode("latin-1")
                    per_position.append(pr)
                    if pr["successful_alignment"] is not None:
                        prev_nl = pr["successful_alignment"]

                    n = pr["position"]
                    mismatch = _check_expected_match(best_byte, n, config.expected)
                    if mismatch is not None:
                        pr["mismatch"] = True
                        pr.update(mismatch)
                        LOG.warning(
                            "run_attack mismatch at position %d: "
                            "expected %r, committed %r — aborting",
                            n, mismatch["expected_byte"], mismatch["committed_byte"],
                        )
                        aborted = True
                        abort_reason = "mismatch"
                        done = True
                        break

                    if best_byte == config.terminator:
                        LOG.info("hit terminator at position %d -> done", pr["position"])
                        done = True
                        break
                    recovered += best_byte
                    LOG.info("recovered so far: %r", recovered.decode("latin-1"))

                position += len(committed)
```

- [ ] **Step 3: Augment the return dict with `aborted` / `abort_reason`.**

Replace the trailing `return {...}` of `run_attack` (around lines 658-664):

```python
    return {
        "recovered": recovered.decode("latin-1"),
        "elapsed_seconds": elapsed,
        "total_guesses": sum(p["guesses"] for p in per_position),
        "per_position": per_position,
        "config_label": config.label,
        "aborted": aborted,
        "abort_reason": abort_reason,
    }
```

- [ ] **Step 4: Sanity-check existing host-side tests still pass.**

```bash
python -m attacker.attack.tests.test_config
python -m attacker.attack.tests.test_engine_helpers
python -m attacker.attack.tests.test_engine_expected
python -m attacker.attack.tests.test_alignment
```

Expected: all four print their `ok` lines.

- [ ] **Step 5: Commit.**

```bash
git add attacker/attack/engine.py
git commit -m "feat(engine): Abort run_attack on expected-byte mismatch"
```

---

### Task 4: Add `cancel_event` parameter for in-flight cancellation

`run_attack` accepts an optional `asyncio.Event`. Between outer position iterations the engine checks `cancel_event.is_set()`; if so, it returns the partial result with `abort_reason="cancelled"`. This is the hook `mitm.py`'s `/cancel` endpoint will use.

**Files:**
- Modify: `attacker/attack/engine.py`

- [ ] **Step 1: Add the parameter to `run_attack`.**

Change the signature (around line 565):

```python
async def run_attack(
    adapter: Adapter,
    config: AttackConfig,
    cancel_event: "asyncio.Event | None" = None,
) -> dict[str, Any]:
```

Add the import at the top of the file if not already present:

```python
import asyncio
```

(Likely already imported via the rest of the engine — verify with `grep '^import asyncio' attacker/attack/engine.py` first; if absent, add it next to the other top-level imports.)

- [ ] **Step 2: Add the cancel check at the top of the outer position loop.**

Inside `run_attack`, at the very top of the `while position < config.max_length and not done:` loop (around line 601):

```python
            while position < config.max_length and not done:
                if cancel_event is not None and cancel_event.is_set():
                    LOG.info("run_attack cancelled by event at position %d", position)
                    aborted = True
                    abort_reason = "cancelled"
                    break

                full_prefix = _trimmed_prefix(
                    config.known_prefix, recovered, config,
                )
                ...
```

- [ ] **Step 3: Sanity-check that the existing helper tests still pass.**

```bash
python -m attacker.attack.tests.test_config
python -m attacker.attack.tests.test_engine_helpers
python -m attacker.attack.tests.test_engine_expected
```

Expected: all print `ok`.

- [ ] **Step 4: Commit.**

```bash
git add attacker/attack/engine.py
git commit -m "feat(engine): Add cancel_event hook to run_attack"
```

---

### Task 5: `mitm.py` — accept top-level `expected` in `/run_attack`

The endpoint pulls `expected` out of the request body and folds it into the config overlay so the engine sees it via the existing config path.

**Files:**
- Modify: `attacker/mitm.py:296-334` (`handle_run_attack`)

- [ ] **Step 1: Read the current endpoint to understand the body parse.**

```bash
sed -n '296,335p' attacker/mitm.py
```

Look at how `body.get("variant", ...)` and `body.get("config", {})` are extracted.

- [ ] **Step 2: Inject `expected` into the overlay.**

Modify `handle_run_attack` (around line 305-321):

```python
    variant = body.get("variant", "direct")
    overrides = dict(body.get("config", {}) or {})
    expected = body.get("expected")
    if expected is not None:
        overrides["expected"] = expected
```

The rest of the function is unchanged — `AttackConfig.overlay(overrides)` will decode the string to bytes.

- [ ] **Step 3: Manually verify the endpoint accepts the new field.**

(Requires the stack to be up; skip if not, and re-run as part of Task 11's smoke.)

```bash
docker compose up -d --build attacker
curl -sX POST http://127.0.0.1:9000/run_attack \
  -H 'Content-Type: application/json' \
  -d '{"variant":"direct","config":{"max_length":1,"max_rounds":1},"expected":"x"}' \
  | python -m json.tool
```

Expected: returns a JSON response with `ok: true, aborted: ...` (the attack will likely fail to set up SSH but the field should be accepted, not rejected).

If the stack isn't up, postpone validation to Task 11.

- [ ] **Step 4: Commit.**

```bash
git add attacker/mitm.py
git commit -m "feat(mitm): Accept top-level expected on /run_attack"
```

---

### Task 6: `mitm.py` — `_CANCEL_EVENT` + `POST /cancel` endpoint

Module-scoped event the running attack consumes. Cleared by `handle_run_attack` on entry; set by `handle_cancel` on demand.

**Files:**
- Modify: `attacker/mitm.py`

- [ ] **Step 1: Find where `_ATTACK_LOCK` is defined and where routes are registered.**

```bash
grep -n "_ATTACK_LOCK\|add_routes\|app.router" attacker/mitm.py
```

Locate the existing `_ATTACK_LOCK = asyncio.Lock()` (around line 283) and the route-registration block.

- [ ] **Step 2: Add `_CANCEL_EVENT` next to `_ATTACK_LOCK`.**

```python
# Guards against concurrent /run_attack calls — two attacks interleaving on
# the shared SSH compressor would destroy each other's measurements.
_ATTACK_LOCK = asyncio.Lock()

# Cleared at the start of each /run_attack; set by /cancel to short-circuit
# an in-flight attack between positions.
_CANCEL_EVENT = asyncio.Event()
```

- [ ] **Step 3: Clear the event in `handle_run_attack` and pass it to the engine.**

Inside `handle_run_attack`, just before the `async with _ATTACK_LOCK:` block:

```python
    LOG.info("HTTP /run_attack: variant=%s label=%r", variant, config.label)
    _CANCEL_EVENT.clear()
    async with _ATTACK_LOCK:
        try:
            result = await run_unified_attack(
                adapter=adapter, config=config, cancel_event=_CANCEL_EVENT,
            )
        except Exception as exc:  # noqa: BLE001
            LOG.exception("unified attack failed")
            return web.json_response(
                {"ok": False, "error": str(exc), "variant": variant}, status=500,
            )
```

(`run_unified_attack` is the alias for `run_attack` — verify the import. If it's imported as `from attacker.attack.engine import run_attack as run_unified_attack`, the kwarg goes through.)

- [ ] **Step 4: Add the `/cancel` handler.**

Insert above the route registration block (or near `handle_run_attack`):

```python
async def handle_cancel(request: web.Request) -> web.Response:
    """Set the cancel event — in-flight /run_attack will return shortly."""
    if _ATTACK_LOCK.locked():
        _CANCEL_EVENT.set()
        return web.json_response({"ok": True, "cancelled": True})
    return web.json_response({"ok": True, "cancelled": False})
```

- [ ] **Step 5: Register the route.**

In the route-registration block (search for an existing `app.router.add_post(...)` for `/run_attack`):

```python
    app.router.add_post("/run_attack", handle_run_attack)
    app.router.add_post("/cancel", handle_cancel)
```

- [ ] **Step 6: Rebuild + smoke (optional pre-flight; full smoke in Task 11).**

```bash
docker compose build attacker && docker compose up -d attacker
curl -sX POST http://127.0.0.1:9000/cancel | python -m json.tool
```

Expected: `{"ok": true, "cancelled": false}` (no attack running).

- [ ] **Step 7: Commit.**

```bash
git add attacker/mitm.py
git commit -m "feat(mitm): Add POST /cancel endpoint backed by asyncio Event"
```

---

### Task 7: `benchmark.py` — add `--early-exit` CLI flag (plumbing only)

Just the flag, propagated into `worker()` as a parameter. No behaviour yet — the next two tasks add `expected` construction and cross-stack stop. This task should leave the benchmark passing without `--early-exit` and accepting `--early-exit` as a no-op.

**Files:**
- Modify: `scripts/benchmark.py`

- [ ] **Step 1: Add the argparse flag.**

In `main()` near the other `ap.add_argument` calls (after `--csv-summary`):

```python
    ap.add_argument("--early-exit", action="store_true",
                    help="abort the run on the first wrong commit; populates "
                         "the engine's `expected` parameter from the known "
                         "password and broadcasts /cancel to all stacks on "
                         "failure")
```

- [ ] **Step 2: Pass `args.early_exit` into worker invocations.**

Modify the `worker()` signature to accept `early_exit: bool` (insert before `results`):

```python
def worker(
    stack_idx: int,
    project: str,
    trial_indices: list[int],
    passwords: list[str],
    variants: list[str],
    pw_alphabet: str,
    config_override: dict,
    early_exit: bool,
    results: list[dict],
    results_lock: threading.Lock,
    failures: list[str],
) -> None:
```

In `main()`, update the `threading.Thread(target=worker, args=...)` call:

```python
            t = threading.Thread(
                target=worker,
                args=(i, p, assignments[i], passwords, variants,
                      args.alphabet, config_override, args.early_exit,
                      results, results_lock, failures),
                daemon=True,
            )
```

- [ ] **Step 3: Run a no-op smoke (no actual attack — just argument parsing).**

```bash
python scripts/benchmark.py --help | grep early-exit
```

Expected: the help line for `--early-exit` is printed.

- [ ] **Step 4: Commit.**

```bash
git add scripts/benchmark.py
git commit -m "feat(benchmark): Add --early-exit CLI flag (plumbing)"
```

---

### Task 8: `benchmark.py` — per-phase `expected` construction

When `early_exit` is on, the benchmark builds `expected_phase1` and `expected_phase2` for each variant and passes them through to `/run_attack`.

**Files:**
- Modify: `scripts/benchmark.py`

- [ ] **Step 1: Extend `_http_run_attack` to accept and forward `expected`.**

Replace the existing function (around line 219-238):

```python
def _http_run_attack(
    attacker_base: str,
    variant: str,
    config_override: dict,
    known_prefix: str,
    alphabet: str,
    max_length: int,
    terminator: str | None = None,
    expected: str | None = None,
) -> dict:
    body_cfg = dict(config_override)
    body_cfg["known_prefix"] = known_prefix
    body_cfg["alphabet"] = alphabet
    body_cfg["max_length"] = max_length
    if terminator is not None:
        body_cfg["terminator"] = terminator
    body: dict[str, Any] = {"variant": variant, "config": body_cfg}
    if expected is not None:
        body["expected"] = expected
    return http(
        f"{attacker_base}/run_attack",
        method="POST",
        body=body,
    )
```

- [ ] **Step 2: Extend `_run_two_phase` to accept and pass per-phase expected.**

Add two new parameters at the end of the signature:

```python
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
    phase2_prefix_from_phase1: Callable,
    phase2_alphabet: str,
    phase2_max_fn: Callable,
    phase2_terminator: str | None,
    strip_trailing: str,
    expected_phase1: str | None = None,
    expected_phase2: str | None = None,
) -> dict:
```

Forward each into the matching `_http_run_attack` call. Replace the two `_http_run_attack(...)` calls inside the function:

```python
    r1 = _http_run_attack(
        attacker_base, variant, base_config,
        phase1_prefix, phase1_alphabet, phase1_max, phase1_terminator,
        expected=expected_phase1,
    )
    phase1_recovered = r1["recovered"]

    r2 = _http_run_attack(
        attacker_base, variant, base_config,
        phase2_prefix_from_phase1(phase1_recovered),
        phase2_alphabet,
        phase2_max_fn(phase1_recovered),
        phase2_terminator,
        expected=expected_phase2,
    )
```

Also propagate the engine's new `aborted` / `abort_reason` fields through the per-trial result dict (after the existing fields, inside `return {...}` of `_run_two_phase`):

```python
    return {
        "recovered": recovered,
        "phase1_guesses": r1.get("total_guesses", -1),
        "phase2_guesses": r2.get("total_guesses", -1),
        "total_guesses": r1.get("total_guesses", 0) + r2.get("total_guesses", 0),
        "elapsed": r1.get("elapsed_seconds", 0) + r2.get("elapsed_seconds", 0),
        "phase1_per_position": r1.get("per_position", []),
        "phase2_per_position": r2.get("per_position", []),
        "phase1_aborted": bool(r1.get("aborted")),
        "phase2_aborted": bool(r2.get("aborted")),
        "abort_reason": r1.get("abort_reason") or r2.get("abort_reason"),
    }
```

- [ ] **Step 3: Extend `run_variant` to compute per-variant expected when requested.**

Modify the signature:

```python
def run_variant(
    variant: str,
    base_config: dict,
    attacker_base: str,
    client_base: str,
    password: str,
    pw_alphabet: str,
    early_exit: bool = False,
) -> dict:
```

Build a small helper at the top of the function:

```python
    if early_exit:
        if variant == "direct" or variant == "beast":
            ep1 = str(len(password)) + "\r"
            ep2 = password + "\r"
        elif variant == "ansible":
            ep1 = chr(len(password)) + "\x00"
            ep2 = password + "\n"
        else:
            ep1 = ep2 = None
    else:
        ep1 = ep2 = None
```

Replace each branch's `_run_two_phase(...)` call to forward these:

```python
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
            phase2_max_fn=lambda s: len(password) + 1,
            phase2_terminator=None,
            strip_trailing="\r",
            expected_phase1=ep1,
            expected_phase2=ep2,
        )
```

Apply the same `expected_phase1=ep1, expected_phase2=ep2,` addition to the `beast` and `ansible` branches.

- [ ] **Step 4: Update the `worker()` call site to pass `early_exit` into `run_variant`.**

Inside `worker()`'s trial loop:

```python
                result = run_variant(variant, config_override,
                                     attacker_base, client_base,
                                     password, pw_alphabet,
                                     early_exit=early_exit)
```

- [ ] **Step 5: Sanity-check argparse + import still works.**

```bash
python -c "import scripts.benchmark; print('ok')"
python scripts/benchmark.py --help | grep early-exit
```

Expected: `ok`, plus the help line.

- [ ] **Step 6: Commit.**

```bash
git add scripts/benchmark.py
git commit -m "feat(benchmark): Build per-variant expected_phase1/2 under --early-exit"
```

---

### Task 9: `benchmark.py` — cross-stack stop event + `/cancel` broadcast

When `--early-exit` is on and a worker observes a failed trial, it sets a shared `threading.Event` and POSTs `/cancel` to every other stack's attacker URL. Other workers check the event before each iteration and exit early.

**Files:**
- Modify: `scripts/benchmark.py`

- [ ] **Step 1: Add the broadcast helper.**

Insert near the other module-level helpers (after `http(...)`):

```python
def _broadcast_cancel(attacker_bases: list[str]) -> None:
    """POST /cancel to every attacker, best-effort. Errors are swallowed —
    a stack that's already wedged or torn down is fine to skip."""
    for base in attacker_bases:
        try:
            http(f"{base}/cancel", method="POST", body={}, timeout=5)
        except Exception:
            pass
```

- [ ] **Step 2: Extend `worker()` signature with the shared state.**

```python
def worker(
    stack_idx: int,
    project: str,
    trial_indices: list[int],
    passwords: list[str],
    variants: list[str],
    pw_alphabet: str,
    config_override: dict,
    early_exit: bool,
    results: list[dict],
    results_lock: threading.Lock,
    failures: list[str],
    stop_event: threading.Event,
    attacker_bases: list[str],
) -> None:
```

After `attacker_base = f"http://{attacker_ip}:9000"` (around line 365), publish the URL under the lock so other workers can see it:

```python
        attacker_base = f"http://{attacker_ip}:9000"
        client_base = f"http://{client_ip}:8000"
        with results_lock:
            attacker_bases.append(attacker_base)
```

- [ ] **Step 3: Honour `stop_event` before each trial.**

At the top of the `for trial_idx in trial_indices:` loop:

```python
    for trial_idx in trial_indices:
        if early_exit and stop_event.is_set():
            return
        password = passwords[trial_idx]
        for variant in variants:
            if early_exit and stop_event.is_set():
                return
            ...
```

- [ ] **Step 4: Trigger broadcast on first failure.**

After the existing `with results_lock: results.append(row)` and the `print(...)` summary line, add:

```python
            with results_lock:
                results.append(row)
            print(f"{tag} trial={trial_idx:3d} variant={variant:7s} "
                  f"guesses={result['total_guesses']:>7} wall={wall:6.1f}s  {status}",
                  flush=True)

            if early_exit and not ok:
                with results_lock:
                    first_failure = not stop_event.is_set()
                    if first_failure:
                        stop_event.set()
                    bases_snapshot = list(attacker_bases)
                if first_failure:
                    print(f"{tag} early-exit: broadcasting /cancel to "
                          f"{len(bases_snapshot)} stack(s)", flush=True)
                    _broadcast_cancel(bases_snapshot)
                return
```

- [ ] **Step 5: Wire shared state through `main()`.**

In `main()`, just before the worker-spawning loop:

```python
        results: list[dict] = []
        results_lock = threading.Lock()
        failures: list[str] = []
        stop_event = threading.Event()
        attacker_bases: list[str] = []
```

Update the `threading.Thread(target=worker, args=...)` call:

```python
            t = threading.Thread(
                target=worker,
                args=(i, p, assignments[i], passwords, variants,
                      args.alphabet, config_override, args.early_exit,
                      results, results_lock, failures,
                      stop_event, attacker_bases),
                daemon=True,
            )
```

- [ ] **Step 6: Sanity-check imports + argparse.**

```bash
python -c "import scripts.benchmark; print('ok')"
python scripts/benchmark.py --help | grep early-exit
```

Expected: `ok` + help line.

- [ ] **Step 7: Commit.**

```bash
git add scripts/benchmark.py
git commit -m "feat(benchmark): Cross-stack stop_event + /cancel broadcast on first failure"
```

---

### Task 10: `benchmark.py` — `success` + `early_exit_triggered` in JSON / CSV

Top-level fields on the JSON dump and a new column on the CSV summary.

**Files:**
- Modify: `scripts/benchmark.py`

- [ ] **Step 1: Compute `early_exit_triggered` and `success` after workers join.**

In `main()`, after the `wall = time.time() - started` line and the `print` of completion, add:

```python
        wall = time.time() - started

        early_exit_triggered = stop_event.is_set()

        print(f"\n=== All trials done in {wall:.1f}s ===")
        if early_exit_triggered:
            print("=== Early-exit was triggered: at least one trial failed "
                  "and the run was aborted ===")
        if failures:
            print("!! some stacks failed:")
            for f in failures:
                print(f"  {f}")

        summary = summarise(results, variants)
        print_summary(summary)

        all_passed = all(s["trials_failed"] == 0 for s in summary.values())
        success = all_passed and not failures and not early_exit_triggered
```

(Move the existing `all_passed = ...` line up so `success` can be computed alongside it, and remove the duplicate `all_passed` calculation that was at the end of the `try:` block.)

- [ ] **Step 2: Add the new fields to the JSON dump.**

Modify the `json.dump({...})` call:

```python
        with open(args.output, "w") as f:
            json.dump({
                "config": {
                    "stacks": args.stacks,
                    "trials": args.trials,
                    "password_length": args.password_length,
                    "alphabet": args.alphabet,
                    "variants": variants,
                    "seed": args.seed,
                    "scenario": args.scenario,
                    "config_label": config_override["label"],
                    "early_exit": args.early_exit,
                },
                "passwords": passwords,
                "results": results,
                "summary": summary,
                "wall_seconds": wall,
                "early_exit_triggered": early_exit_triggered,
                "success": success,
            }, f, indent=2)
        print(f"\nDetailed results -> {args.output}")
```

- [ ] **Step 3: Add `early_exit_triggered` column to the CSV.**

In the CSV-writing block, extend the header and each row:

```python
        with open(args.csv_summary, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "variant", "scenario", "trials_passed",
                "per_attack_min", "per_attack_max", "per_attack_avg", "per_attack_total",
                "per_position_count",
                "per_position_min", "per_position_max", "per_position_avg",
                "fork_triggered_positions", "fork_overhead_guesses",
                "early_exit_triggered",
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
                    s["fork_triggered_positions"], s["fork_overhead_guesses"],
                    "true" if early_exit_triggered else "false",
                ])
        print(f"CSV summary -> {args.csv_summary}")
```

- [ ] **Step 4: Update the return statement.**

Replace the trailing return:

```python
        return 0 if success else 1
```

(Previously: `return 0 if all_passed and not failures else 1`.)

- [ ] **Step 5: Sanity-check imports + argparse.**

```bash
python -c "import scripts.benchmark; print('ok')"
```

- [ ] **Step 6: Commit.**

```bash
git add scripts/benchmark.py
git commit -m "feat(benchmark): Emit success + early_exit_triggered in JSON and CSV"
```

---

### Task 11: `sweep_min_margin.sh` — `EARLY_EXIT=1` default

**Files:**
- Modify: `scripts/sweep_min_margin.sh`

- [ ] **Step 1: Add the env var with default `1`.**

In the env-var block (around line 30-36):

```bash
STACKS="${STACKS:-20}"
TRIALS="${TRIALS:-100}"
FIXED_NL_DIRECT="${FIXED_NL_DIRECT:-2}"
FIXED_NL_ANSIBLE="${FIXED_NL_ANSIBLE:-1}"
MM_START="${MM_START:-8}"
MM_STEP="${MM_STEP:-8}"
MM_MAX="${MM_MAX:-128}"
EARLY_EXIT="${EARLY_EXIT:-1}"
```

- [ ] **Step 2: Conditionally append `--early-exit` to the benchmark invocation.**

Locate the `python3 scripts/benchmark.py \` block and modify:

```bash
            ee_args=()
            if [ "$EARLY_EXIT" = "1" ]; then
                ee_args+=(--early-exit)
            fi
            if python3 scripts/benchmark.py \
                --stacks "$STACKS" \
                --trials "$TRIALS" \
                --variants "$variant" \
                --scenario "$preset" \
                --min-margin "$mm" \
                --output "$results_json" \
                --csv-summary "$summary_csv" \
                "${ee_args[@]}" \
                "${extra_args[@]}" >/dev/null 2>&1; then
                echo "### $scenario_key/$variant mm=$mm: 100% success — stop"
                succeeded=1
                break
            fi
```

- [ ] **Step 3: Update the header comments.**

Modify the comment block at the top:

```bash
# Knobs (env vars):
#   STACKS           (default 4)    parallel docker-compose projects per run
#   TRIALS           (default 50)   passwords attempted per run
#   FIXED_NL_DIRECT  (default 2)    pinned alignment length for direct
#   FIXED_NL_ANSIBLE (default 1)    pinned alignment length for ansible
#   MM_START         (default 8)    starting min_margin
#   MM_STEP          (default 8)    increment
#   MM_MAX           (default 128)  upper bound (inclusive)
#   EARLY_EXIT       (default 1)    if 1, pass --early-exit to benchmark.py
#                                   so a doomed mm-step aborts on first
#                                   wrong commit instead of running every
#                                   trial to completion
```

- [ ] **Step 4: Bash syntax check.**

```bash
bash -n scripts/sweep_min_margin.sh && echo OK
```

Expected: `OK`.

- [ ] **Step 5: Commit.**

```bash
git add scripts/sweep_min_margin.sh
git commit -m "feat(sweep): Default EARLY_EXIT=1 to fast-fail doomed mm-steps"
```

---

### Task 12: End-to-end smoke

Manual integration test. The host-side test suite covers the helpers; this task confirms the benchmark's full path works against a live stack. Designed to take 5-10 minutes wall-clock.

- [ ] **Step 1: Rebuild the attacker image (engine + mitm changes are baked into it).**

```bash
docker compose build attacker
```

- [ ] **Step 2: Smoke a single-stack benchmark with `--early-exit` at a known-good `min_margin`.**

```bash
python scripts/benchmark.py \
  --stacks 1 --trials 2 \
  --variants direct \
  --scenario all-opts \
  --early-exit \
  --output /tmp/ee_ok.json \
  --csv-summary /tmp/ee_ok.csv
```

Expected: both trials pass, console summary shows `trials_passed: 2`, `/tmp/ee_ok.json` has `"success": true`, `"early_exit_triggered": false`. Exit code `0`.

- [ ] **Step 3: Smoke a deliberately-failing run (low min_margin → wrong commits).**

```bash
python scripts/benchmark.py \
  --stacks 2 --trials 4 \
  --variants direct \
  --scenario baseline --fixed-nl 2 \
  --min-margin 1 \
  --early-exit \
  --output /tmp/ee_fail.json \
  --csv-summary /tmp/ee_fail.csv
```

Expected:
- The run aborts well before all 4 trials complete (`min_margin=1` is too low — trial 1 will mis-commit fast).
- Console shows the `early-exit: broadcasting /cancel to N stack(s)` line.
- `/tmp/ee_fail.json` has `"early_exit_triggered": true`, `"success": false`. Exit code `1`.
- At least one per-position record contains `"mismatch": true` with `expected_byte` and `committed_byte` fields.

Verify:

```bash
python -c "
import json
d = json.load(open('/tmp/ee_fail.json'))
print('success:', d['success'])
print('early_exit_triggered:', d['early_exit_triggered'])
mismatches = [p for r in d['results']
              for p in r['phase1_per_position'] + r['phase2_per_position']
              if p.get('mismatch')]
print('mismatch count:', len(mismatches))
if mismatches:
    print('sample:', {k: v for k, v in mismatches[0].items()
                     if k in ('position','expected_byte','committed_byte')})
"
```

Expected:
```
success: False
early_exit_triggered: True
mismatch count: >= 1
sample: {'position': N, 'expected_byte': '...', 'committed_byte': '...'}
```

- [ ] **Step 4: Confirm `verify_*.py` still work (they don't pass expected, must run to completion).**

```bash
python scripts/verify_direct.py
```

Expected: full hunter2 recovery, exit code `0`. Same green output as before this plan.

- [ ] **Step 5: Confirm `/cancel` is a no-op when idle.**

```bash
curl -sX POST http://127.0.0.1:9000/cancel | python -m json.tool
```

Expected: `{"ok": true, "cancelled": false}`.

- [ ] **Step 6: Tear down stacks if they were brought up by the benchmark.**

```bash
docker compose down -v
```

- [ ] **Step 7: Commit any final test/docs adjustments discovered during the smoke.**

If smoke uncovered a bug, fix it in the relevant earlier task's file and add a bug-fix commit:

```bash
git commit -m "fix(<area>): <what>"
```

If everything worked first try, no commit needed in this task — the work is done.

---

## Self-review

**Spec coverage:**
- Engine `expected` field + bytes-overlay decoding → Task 1
- Engine mismatch check at the commit loop → Tasks 2 + 3
- Engine `cancel_event` hook → Task 4
- Engine return shape additions (`aborted`, `abort_reason`) → Task 3
- Per-position mismatch fields → Task 3
- HTTP top-level `expected` + module-scoped event + `/cancel` → Tasks 5 + 6
- Benchmark `--early-exit` flag → Task 7
- Per-variant phase1/phase2 expected (decimal-ASCII for direct/beast, single-byte for ansible) → Task 8
- Cross-stack stop event + `/cancel` broadcast → Task 9
- JSON `success` + `early_exit_triggered`; CSV column → Task 10
- Sweep `EARLY_EXIT=1` default → Task 11
- Verify scripts unchanged → not modified by any task; called out in Task 12 step 4
- Terminator-position mismatch is detected → covered by `_check_expected_match` test in Task 2 + helper docstring + Task 3 ordering (mismatch before terminator)
- Tests for the helper → Task 2

**Type / signature consistency check:**
- `_check_expected_match(committed_byte: bytes, position: int, expected: bytes | None) -> dict | None` — same signature in Task 2 (definition, tests) and Task 3 (call site).
- `run_attack(adapter, config, cancel_event=None)` — kwarg name `cancel_event` matches Task 4 definition and Task 6 call site (`cancel_event=_CANCEL_EVENT`).
- `_run_two_phase(..., expected_phase1=None, expected_phase2=None)` and `run_variant(..., early_exit=False)` — signatures defined in Task 8 and called consistently in Task 9 / `worker()` extension.
- `worker(..., early_exit, results, results_lock, failures, stop_event, attacker_bases)` — same parameter order in Task 9 and Task 9 step 5 thread-spawning loop.
- `_broadcast_cancel(attacker_bases: list[str])` — sole consumer in Task 9.

**Placeholder scan:** no TBDs, every step has either runnable commands or full code blocks. Task 12 is integration smoke and intentionally exercises the live stack rather than asserting in code.

**Aiohttp gap:** the engine's `run_attack` imports aiohttp eagerly, which is unavailable on host. The plan handles this by pulling the mismatch decision into a pure helper (Task 2) that's host-testable, and validating the engine integration via Task 12's stack smoke. Spec acknowledged this; plan respects it.
