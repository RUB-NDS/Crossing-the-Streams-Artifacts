# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

`README.md` is the canonical reference for layout, the architecture
overview, the HTTP control surface, and how to run the artifact. The
*paper* (not in the repo) covers the attacker model, attack algorithm,
the constants the attack depends on, and the security analysis. This
file covers only what's not there: repo workflow, cross-file
architecture, and the pitfalls that bite during edits.

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
# --compensation = noise-compensation configuration (Section 4.3): NO, FS,
#                  AS, CE, AS+CE -- the five configurations of Table 3.
#                  NO and CE need --alignment-length L.
python scripts/benchmark.py --stacks 4 --trials 100 --compensation AS+CE
python scripts/benchmark.py --stacks 2 --trials 50 --scenarios direct \
    --compensation NO --alignment-length 1

# Commit-margin (the paper's mu) sweep harness (Table 3).
# Exit-code contract: 0 = 100% success, 1 = algorithmic miss (sweep can
# bump commit_margin), 2 = technical/infrastructure failure (abort).
scripts/sweep_commit_margin.sh

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
the pinned host key. This is not a bug; it is the attacker model of
Section 4.1 (passive on-path eavesdropper plus network or web
attacker).

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
`benchmark_summary.csv` (per-`(scenario, compensation)` aggregates).
`scripts/stats.py <results.json>` prints n / min / max / mean / median /
stdev over the `total_guesses` field of passing trials.

## Editing gotchas

- **Rebuild after Python edits.** `attacker/` and `client/` sources are
  `COPY`'d at image build time, not bind-mounted. Host scripts won't
  see changes until the relevant service is rebuilt.
- **Do not casually change the tuned constants.**
  `flush_bytes=32768` (32 KiB, deflate's maximum search-buffer size) and
  `flush_pool="secrets_random"` (direct/browser),
  `guess_prefill_bytes=16384` (browser only, the paper's "random data
  prepended to the guess body"), alignment pool `0x80..0x8F` (8-bit
  static-Huffman literals), the per-scenario `commit_margin`, and the
  adapter-specific ordering are explained in the paper (Sections 4
  and 5) and in adapter docstrings. `outlier_threshold`,
  `constant_prefix_trim`, and `candidate_fork_on_stall` are
  implementation details with no counterpart in the paper. Changes here
  routinely collapse attack throughput.
- **Terminator must be in the alphabet.** The engine auto-appends
  `terminator` to `alphabet` if missing; omit at your peril if you
  bypass the overlay path.
- **Cipher assumption.** The alignment sweep assumes
  `chacha20-poly1305@openssh.com`'s 8-byte padding granularity
  (`alignment_lengths=[0..7]`). AES-based modes pad to 16 bytes and
  would need `[0..15]`, growing the sweep -- and with it the guess
  count -- linearly (paper Section 8.1, "Cipher Dependence"). The
  negotiated cipher is visible at `GET http://localhost:8000/status`.
- **Ansible `known_length` mode is the speed knob, not a correctness
  knob.** After the first position locks the winning alignment length,
  pinning to it skips the 8x sweep. If the sweep fails to lock, the
  trial fails -- don't silently disable the sweep.
- **Sweep harness exit codes.** `scripts/sweep_commit_margin.sh` relies
  on `benchmark.py` distinguishing rc=1 (algorithmic miss; bump
  `commit_margin` and retry) from rc=2 (technical/infrastructure
  failure; abort entire sweep). Don't muddle the two.
- **`evaluation/` is curated, not raw sweep output.** A fresh
  `scripts/sweep_commit_margin.sh` run writes to
  `results/{COMPENSATION}/benchmark_*_{scenario}_cmN.{json,csv}`
  (compensation-first, uppercase labels). The committed Table-3 dataset
  is at
  `evaluation/{scenario}/{compensation}/benchmark_*_{scenario}_cmN.{json,csv}`
  (scenario-first, lowercase labels). If you re-run the sweep, don't dump
  straight into `evaluation/`: it'll mix layouts and clobber whichever
  rows the paper cites. Land new runs under `results/` and reorganise
  deliberately. The committed files were restructured to the current
  schema (`scenarios` / `compensation` / `config_label`, `-cmN` labels,
  LF + trailing newline), so they and fresh sweep output share one shape.
- **`evaluation/` holds exactly Table 3's 13 cells.** Five
  configurations x three scenarios minus the four n/a cells (browser
  NO/CE) minus nothing else. If you add a configuration, it belongs
  under `results/` until the paper reports it.

## File -> purpose quick reference

- `attacker/attack/engine.py` -- round loop, ranking, metrics, the
  noise-compensation strategies of Section 4.3, the `run_attack()`
  coroutine, and `resolve_stalled_position()` (fork-on-stall fallback,
  not part of the paper and off in every configuration).
  Transport-agnostic.
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
  `COMPENSATION_PRESETS` is the single source of truth for the
  configuration toggle combinations.
- `scripts/sweep_commit_margin.sh` -- commit-margin sweep that drives
  `benchmark.py` per (scenario, compensation). Exit-code contract
  above.
- `scripts/pin-hosts.sh` -- DNS-pinning entrypoint shared by the
  attacker / client / server images.
- `scripts/stats.py` -- summary stats over a `benchmark_results.json`.
- `scripts/verify_*.py` -- per-scenario preconditions + one `hunter2`
  recovery end-to-end.
- `evaluation/{scenario}/{compensation}/` -- committed Table 3 dataset.
  One `(benchmark_results_*.json, benchmark_summary_*.csv)` pair per
  commit-margin step the sweep walked through; the highest-`cmN` pair is
  the converged 100 %-recovery run. Browser has no `no/` or `ce/`
  subtree: both presuppose a known winning alignment length, which the
  browser noise floor does not support -- the n/a cells of Table 3.
  Feed any `benchmark_results_*.json` to `scripts/stats.py` for
  per-cell mean/median/stdev.
