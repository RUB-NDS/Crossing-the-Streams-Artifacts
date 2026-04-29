# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

`README.md` is the canonical reference for layout, the architecture
overview, the HTTP control surface, and how to run the artifact. The
*paper* (not in the repo) covers the threat model, attack algorithm,
load-bearing constants, and security analysis. This file covers only
what's not there: repo workflow, cross-file architecture, and the
pitfalls that bite during edits.

## Common commands

```bash
# Bring up the five-service stack (keygen -> redis -> server -> attacker -> client)
docker compose up -d --build

# After editing Python in attacker/ or client/, rebuild -- sources are COPY'd, not bind-mounted
docker compose build attacker && docker compose up -d attacker
docker compose build client   && docker compose up -d client

# End-to-end verification (each ~ 2-17 min)
python scripts/verify_direct.py
python scripts/verify_browser.py
python scripts/verify_ansible.py

# Scenario benchmark (multi-stack, isolated compose projects).
# --scenarios   = subset of {direct, browser, ansible}.
# --optimization = paper Table 2 labels: NO, FS, AS, CE, FSCE, ASCE.
python scripts/benchmark.py --stacks 4 --trials 100 --optimization ASCE
python scripts/benchmark.py --stacks 2 --trials 50 --scenarios direct --optimization NO --fixed-al 1

# Min-margin (commit-margin) sweep harness (Table 2 in the paper).
# Exit-code contract: 0 = 100% success, 1 = algorithmic miss (sweep can
# bump min_margin), 2 = technical/infrastructure failure (abort).
scripts/sweep_min_margin.sh

# Watch per-byte progress while an attack runs
docker compose logs -f attacker

# Engine-helper sanity tests (pure-logic, run on the host, no container needed)
python -m attacker.attack.tests.test_engine_helpers
python -m attacker.attack.tests.test_engine_expected
python -m attacker.attack.tests.test_alignment
python -m attacker.attack.tests.test_config
python -m attacker.attack.tests.test_fork
```

There is **no lint step and no integration test suite beyond the verify
/ benchmark scripts** -- a successful attack recovery *is* the test.
Host scripts use stdlib only (`urllib`, `json`) and target
`http://127.0.0.1:9000` (attacker) and `http://127.0.0.1:8000` (client);
those ports are mapped only by the default `docker-compose.yml`.

## Architecture that spans files

### Engine + adapter split

All three scenarios share `attacker/attack/engine.py` (round loop,
candidate ranking, alignment sweep, per-position metrics, outlier
retry). The engine calls one method on the adapter:

```python
async def measure_once(prefix, candidate, alignment) -> int   # wire-byte count
```

Transport-specific ordering (flush / open measure channel / trigger
secret / send guess / read packet log) lives inside the adapter, not the
engine. The three adapters:

- `attacker/attack/adapters/direct.py` -- raw TCP dial to the client's
  exposed tunnel port (`TUNNEL_PORT`, default 6379). Requires a flush
  before every measurement.
- `attacker/attack/adapters/browser.py` -- drives the victim's browser
  over `BrowserBridge` (WebSocket) to call `navigator.sendBeacon()`.
  Regenerates the flush block on **every** measurement (not per round
  -- a cached flush creates a persistent LZ77 bias that averaging
  cannot remove).
- `attacker/attack/adapters/ansible.py` -- triggers a fresh
  `ansible-playbook` run per guess; dials the Ansible `LocalForward`
  port on the client (`ANSIBLE_TUNNEL_PORT`, default 15432). No flush
  needed (fresh SSH connection -> empty zlib window).

Adapter selection happens at one place: `handle_run_attack` in
`attacker/mitm.py`. The request body is
`{"scenario": "direct|browser|ansible", "config": {...}}`; each adapter
exposes a `default_config()` classmethod, and `AttackConfig.overlay()`
applies caller overrides on top (`attacker/attack/config.py`).

### Why the client connects to the attacker, not the server

The client launches `ssh -N -C -v` with `SSH_TARGET_HOST=attacker` and
`SSH_TARGET_PORT=2222`, but pins the **real** server's host key in
`known_hosts`. `attacker/mitm.py` is a passive TCP forwarder between
`:2222` and `server:22` -- it never terminates or decrypts SSH. Any
active in-the-middle attempt is rejected at the SSH layer because of
the pinned host key. This is not a bug; it is the threat model (passive
on-path observer).

### The attacker container does three things in one process

`attacker/mitm.py` owns:

1. An `asyncio.start_server` TCP forwarder (`:2222` -> `server:22`).
2. A `scapy.AsyncSniffer` on `eth0` feeding a thread-safe `PacketLog`.
   Requires `NET_ADMIN` + `NET_RAW` caps (set in `docker-compose.yml`).
3. An `aiohttp` control API on `:9000`, plus a `BrowserBridge` WebSocket
   used by the browser adapter.

### Browser-injection exploit page is served by the attacker

The exploit page is `attacker/exploit.html`, served at
`http://attacker:9000/exploit` by the attacker's aiohttp process. The
client container launches a headless **Firefox** via Playwright that
navigates to that URL. Firefox is used because the page origin is
`http://attacker:9000` and the `sendBeacon` target is
`http://localhost:6379` -- Chromium and WebKit would preflight this
cross-origin public->loopback request under Private Network Access and
drop the request body, defeating the body-in-request injection.

### Benchmark stack isolation

`scripts/benchmark.py` spawns N independent docker-compose projects via
the `docker-compose.bench.yml` overlay, which:

- Project-scopes every `container_name` using `${COMPOSE_PROJECT_NAME}`.
- Drops host port mappings (`ports: !override []`) -- the benchmark
  script dials each attacker / client directly on their docker-bridge
  IPs, discovered via `docker inspect`.
- Tags images under `ssh-compression-poc-bench/<service>:latest` so
  `docker compose build` runs once and subsequent `up`s reuse it.

To survive 25+ parallel stacks the bench overlay also runs
`scripts/pin-hosts.sh` as the container ENTRYPOINT in every image,
which writes sibling container IPs into `/etc/hosts` so the main
process never queries Docker's embedded DNS resolver under burst load.

Results: `benchmark_results.json` (per-trial, per-position detail) and
`benchmark_summary.csv` (per-`(scenario, optimization)` aggregates).
`scripts/stats.py <results.json>` prints n / min / max / mean / median /
stdev over the `total_guesses` field of passing trials.

## Editing gotchas

- **Rebuild after Python edits.** `attacker/` and `client/` sources are
  `COPY`'d at image build time, not bind-mounted. Host scripts won't
  see changes until the relevant service is rebuilt.
- **Do not casually change the load-bearing constants.**
  `flush_bytes=32768` (32 KiB, the zlib LZ77 window size) and `flush_pool="secrets_random"` (direct/browser),
  `guess_prefill_bytes=16384` (browser only), alignment pool
  `0x80..0x8F`, the per-scenario `min_margin`, the adapter-specific
  ordering, and `outlier_threshold` are all explained in the paper
  (Sections 4 and 5) and in adapter docstrings. Changes here routinely
  collapse attack throughput.
- **Terminator must be in the alphabet.** The engine auto-appends
  `terminator` to `alphabet` if missing; omit at your peril if you
  bypass the overlay path.
- **Cipher assumption.** The alignment sweep assumes
  `chacha20-poly1305@openssh.com`'s 8-byte padding granularity
  (`alignment_lengths=[0..7]`). AES-CTR+HMAC-ETM would need `[0..15]`;
  the negotiated cipher is visible at
  `GET http://localhost:8000/status`.
- **Ansible `fixed_single` mode is the speed knob, not a correctness
  knob.** After the first position locks the winning alignment length,
  pinning to it skips the 8x sweep. If the sweep fails to lock, the
  trial fails -- don't silently disable the sweep.
- **Sweep harness exit codes.** `scripts/sweep_min_margin.sh` relies on
  `benchmark.py` distinguishing rc=1 (algorithmic miss; bump
  `min_margin` and retry) from rc=2 (technical/infrastructure failure;
  abort entire sweep). Don't muddle the two.

## File -> purpose quick reference

- `attacker/attack/engine.py` -- round loop, ranking, metrics,
  `run_attack()` coroutine, and `resolve_stalled_position()`
  (fork-on-stall fallback). Transport-agnostic.
- `attacker/attack/config.py` -- `AttackConfig`, `AlignmentMode`,
  `overlay()` for JSON -> dataclass marshalling.
- `attacker/attack/alignment.py` -- `_ALIGNMENT_POOL`, `make_alignment()`.
- `attacker/attack/adapters/{direct,browser,ansible}.py` -- per-scenario
  ordering + `default_config()`.
- `attacker/attack/adapters/browser_bridge.py` -- WebSocket dispatcher
  used only by the browser adapter.
- `attacker/mitm.py` -- container `CMD`; forwarder + sniffer +
  `/run_attack` dispatch.
- `client/client.py` -- SSH subprocess manager, redis-py, Firefox
  launcher (navigates to the attacker-served exploit page), ansible
  runner.
- `scripts/benchmark.py` -- multi-stack scenario harness;
  `SCENARIO_PRESETS` is the single source of truth for the preset
  toggle combinations.
- `scripts/sweep_min_margin.sh` -- min-margin sweep that drives
  `benchmark.py` per (scenario, optimization). Exit-code contract above.
- `scripts/pin-hosts.sh` -- DNS-pinning entrypoint shared by the
  attacker / client / server images.
- `scripts/stats.py` -- summary stats over a `benchmark_results.json`.
- `scripts/verify_*.py` -- per-scenario preconditions + one `hunter2`
  recovery end-to-end.
