# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`README.md` is the canonical reference for the threat model, attack
algorithm, load-bearing constants, and HTTP control surface. Read it
first. This file covers only what's not there: repo workflow,
cross-file architecture, and the pitfalls that bite during edits.

## Common commands

```bash
# Bring up the five-service stack (keygen → redis → server → attacker → client)
docker compose up -d --build

# After editing Python in attacker/ or client/, rebuild — sources are COPY'd, not bind-mounted
docker compose build attacker && docker compose up -d attacker
docker compose build client   && docker compose up -d client

# End-to-end verification (each ≈ 2–4 min)
python scripts/verify_direct.py
python scripts/verify_beast.py
python scripts/verify_ansible.py

# Scenario benchmark (multi-stack, isolated compose projects)
python scripts/benchmark.py --stacks 4 --trials 100 --scenario all-opts
python scripts/benchmark.py --stacks 2 --trials 50 --variants direct --scenario baseline --fixed-nl 1

# Watch per-byte progress while an attack runs
docker compose logs -f attacker

# Engine-helper sanity tests (pure-logic, run on the host, no container needed)
python -m attacker.attack.tests.test_engine_helpers
python -m attacker.attack.tests.test_alignment
python -m attacker.attack.tests.test_config
```

There is **no lint step and no integration test suite beyond the verify
/ benchmark scripts** — a successful attack recovery *is* the test.
Host scripts use stdlib only (`urllib`, `json`) and target
`http://127.0.0.1:9000` (attacker) and `http://127.0.0.1:8000` (client);
those ports are mapped only by the default `docker-compose.yml`.

## Architecture that spans files

### Engine + adapter split (the core refactor)

All three variants share **`attacker/attack/engine.py`** (round loop,
candidate ranking, alignment sweep, per-position metrics, outlier
retry). The engine calls one method on the adapter:

```python
async def measure_once(prefix, candidate, alignment) -> int   # wire-byte count
```

Transport-specific ordering (flush / open measure channel / trigger
secret / send guess / read log) lives inside the adapter, not the
engine. The three adapters:

- `attacker/attack/adapters/direct.py` — raw TCP dial to the client's
  exposed tunnel port (`TUNNEL_PORT`, default 6379). Requires a flush
  before every measurement.
- `attacker/attack/adapters/beast.py` — drives the victim's browser
  over `BrowserBridge` (WebSocket) to call `navigator.sendBeacon()`.
  Regenerates the flush block on **every** measurement (not per
  round — a cached flush creates a persistent LZ77 bias that
  averaging cannot remove).
- `attacker/attack/adapters/ansible.py` — triggers a fresh
  `ansible-playbook` run per guess; dials the Ansible `LocalForward`
  port on the client (`ANSIBLE_TUNNEL_PORT`, default 15432). No
  flush needed (fresh SSH connection → empty zlib window).

Adapter selection happens at one place: `handle_run_attack` in
`attacker/mitm.py:292`. The request body is
`{"variant": "direct|beast|ansible", "config": {...}}`; each adapter
exposes a `default_config()` classmethod, and `AttackConfig.overlay()`
applies caller overrides on top (`attacker/attack/config.py`).

### Why the client connects to the attacker, not the server

The client launches `ssh -N -C -v` with `SSH_TARGET_HOST=attacker`
and `SSH_TARGET_PORT=2222`, but pins the **real** server's host key
in `known_hosts`. `attacker/mitm.py` is a passive TCP forwarder
between `:2222` and `server:22` — it never terminates or decrypts
SSH. Any active in-the-middle attempt is rejected at the SSH layer
because of the pinned host key. This is not a bug; it is the threat
model (passive on-path observer).

### The attacker container does three things in one process

`attacker/mitm.py` owns:
1. An `asyncio.start_server` TCP forwarder (`:2222` → `server:22`).
2. A `scapy.AsyncSniffer` on `eth0` feeding a thread-safe
   `PacketLog`. Requires `NET_ADMIN` + `NET_RAW` caps (set in
   `docker-compose.yml`).
3. An `aiohttp` control API on `:9000`, plus a `BrowserBridge`
   WebSocket used by the BEAST adapter.

### BEAST exploit page is served by the attacker

The exploit page is `attacker/exploit.html`, served at
`http://attacker:9000/exploit` by the attacker's aiohttp process
(route registered in `attacker/mitm.py`). The client container
launches a headless **Firefox** via Playwright that navigates to
that URL. Firefox is used because the page origin is
`http://attacker:9000` and the `sendBeacon` target is
`http://localhost:6379` — Chromium and WebKit would preflight this
cross-origin public→loopback request under Private Network Access
and drop the request body, defeating the body-in-request injection.
Firefox as of early 2026 does not implement PNA, so the full body
is sent directly.

The browser still lives in the client container: it represents the
victim's browser, which must be co-located with the SSH client to
reach the loopback-bound forward on `localhost:6379`. **If you edit
BEAST JS, edit `attacker/exploit.html`** — there is no inline copy
in `client/client.py` anymore.

### Benchmark stack isolation

`scripts/benchmark.py` spawns N independent docker-compose projects
via the `docker-compose.bench.yml` overlay, which:

- Project-scopes every `container_name` using
  `${COMPOSE_PROJECT_NAME}`.
- Drops host port mappings (`ports: !override []`) — the benchmark
  script dials each attacker / client directly on their docker-bridge
  IPs, discovered via `docker inspect`.
- Tags images under `ssh-compression-poc-bench/<service>:latest` so
  `docker compose build` runs once and subsequent `up`s reuse it.

Results: `benchmark_results.json` (per-trial, per-position detail)
and `benchmark_summary.csv` (per-`(variant, scenario)` aggregates).

## Editing gotchas

- **Rebuild after Python edits.** `attacker/` and `client/` sources
  are `COPY`'d at image build time, not bind-mounted. Host scripts
  won't see changes until the relevant service is rebuilt.
- **Do not casually change the load-bearing constants.**
  `flush_bytes=33000` and `flush_pool="secrets_random"` (direct/BEAST),
  `guess_prefill_bytes=16384` (BEAST only), alignment pool `0x80..0x8F`,
  the per-variant `min_margin`, the adapter-specific ordering, and
  `outlier_threshold` are all explained in README §"Load-bearing
  constants" and in docstrings. Changes here routinely collapse attack
  throughput.
- **Terminator must be in the alphabet.** The engine auto-appends
  `terminator` to `alphabet` if missing (see commit `d1a6c85`); omit
  at your peril if you bypass the overlay path.
- **Cipher assumption.** The alignment sweep assumes
  `chacha20-poly1305@openssh.com`'s 8-byte padding granularity
  (`alignment_lengths=[0..7]`). AES-CTR+HMAC-ETM would need
  `[0..15]`; the negotiated cipher is visible at
  `GET http://localhost:8000/status`.
- **Ansible `fixed_single` mode is the speed knob, not a correctness
  knob.** After the first position locks the winning alignment
  length, pinning to it skips the 8× sweep and is ~8× faster. If the
  sweep fails to lock, the trial fails — don't silently disable the
  sweep.

## File → purpose quick reference

- `attacker/attack/engine.py` — round loop, ranking, metrics,
  `run_attack()` coroutine, and `resolve_stalled_position()` (fork-on-stall
  fallback). Transport-agnostic.
- `attacker/attack/config.py` — `AttackConfig`, `AlignmentMode`,
  `overlay()` for JSON → dataclass marshalling.
- `attacker/attack/alignment.py` — `_ALIGNMENT_POOL`,
  `make_alignment()`. The 0x80..0x8F bytes and why.
- `attacker/attack/adapters/{direct,beast,ansible}.py` — per-variant
  ordering + `default_config()`.
- `attacker/attack/adapters/browser_bridge.py` — WebSocket dispatcher
  used only by BEAST.
- `attacker/mitm.py` — container `CMD`; forwarder + sniffer +
  `/run_attack` dispatch.
- `client/client.py` — SSH subprocess manager, redis-py, Firefox
  launcher (navigates to the attacker-served exploit page), ansible
  runner.
- `scripts/benchmark.py` — multi-stack scenario harness;
  `SCENARIO_PRESETS` is the single source of truth for the preset
  toggle combinations.
- `scripts/verify_*.py` — per-variant preconditions + one
  `hunter2` recovery end-to-end.
- `docs/superpowers/{specs,plans}/` — the design spec and
  18-task implementation plan behind the unified engine refactor.
