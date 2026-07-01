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
python scripts/verify_browser_pna.py   # PNA Chromium; seeded {len,pw0,pw1} + real tail
python scripts/verify_ansible.py

# Scenario benchmark (multi-stack, isolated compose projects).
# --scenarios   = subset of {direct, browser, browser_pna, ansible}.
# --optimization = paper Table 2 labels: NO, FS, AS, CE, FSCE, ASCE.
# --seed-len    = browser_pna only: seeded leading bytes (default 2).
python scripts/benchmark.py --stacks 4 --trials 100 --optimization ASCE
python scripts/benchmark.py --stacks 2 --trials 50 --scenarios direct --optimization NO --fixed-al 1
# browser_pna: 10-char pw = 2 seeded + 8 truly recovered (comparable to browser).
python scripts/benchmark.py --stacks 4 --trials 100 --scenarios browser_pna --optimization ASCE --password-length 10 --seed-len 2

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
python -m attacker.attack.tests.test_url_safe_alignment   # browser_pna alignment pool
python -m attacker.attack.tests.test_pna_path_builder     # browser_pna path/anchor/seed
```

There is **no lint step and no integration test suite beyond the verify
/ benchmark scripts** -- a successful attack recovery *is* the test.
Host scripts use stdlib only (`urllib`, `json`) and target
`http://127.0.0.1:9000` (attacker) and `http://127.0.0.1:8000` (client);
those ports are mapped only by the default `docker-compose.yml`.

## Architecture that spans files

### Engine + adapter split

All four scenarios share `attacker/attack/engine.py` (round loop,
candidate ranking, alignment sweep, per-position metrics, outlier
retry). The engine calls one method on the adapter:

```python
async def measure_once(prefix, candidate, alignment) -> int   # wire-byte count
```

Transport-specific ordering (flush / open measure channel / trigger
secret / send guess / read packet log) lives inside the adapter, not the
engine. The four adapters:

- `attacker/attack/adapters/direct.py` -- raw TCP dial to the client's
  exposed tunnel port (`TUNNEL_PORT`, default 6379). Requires a flush
  before every measurement.
- `attacker/attack/adapters/browser.py` -- drives the victim's browser
  over `BrowserBridge` (WebSocket) to call `navigator.sendBeacon()`.
  Regenerates the flush block on **every** measurement (not per round
  -- a cached flush creates a persistent LZ77 bias that averaging
  cannot remove).
- `attacker/attack/adapters/browser_pna.py` -- the PNA sibling of
  `browser.py`. Drives the pinned **Chromium** (not Firefox) over a
  **separate** `BrowserBridge` (`/ws_pna`). Because a PNA-enforcing
  browser answers the cross-origin private->loopback fetch with an
  OPTIONS preflight that strips the body, the guess rides in the
  preflight's **URL path** (`inject_preflight`), not the body. The
  CR/LF wall this creates makes `{length, pw0, pw1}` un-leakable
  (seeded); the tail `pw2..pw(n-1)` is recovered length-bounded
  (`terminator=b""`). Uses URL-safe byte pools (see gotchas).
- `attacker/attack/adapters/ansible.py` -- triggers a fresh
  `ansible-playbook` run per guess; dials the Ansible `LocalForward`
  port on the client (`ANSIBLE_TUNNEL_PORT`, default 15432). No flush
  needed (fresh SSH connection -> empty zlib window).

Adapter selection happens at one place: `handle_run_attack` in
`attacker/mitm.py`. The request body is
`{"scenario": "direct|browser|browser_pna|ansible", "config": {...}}`;
each adapter exposes a `default_config()` classmethod, and
`AttackConfig.overlay()` applies caller overrides on top
(`attacker/attack/config.py`).

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

The **`browser_pna`** scenario turns that defeat into the attack. A
**second** exploit page `attacker/exploit_pna.html` is served at
`/exploit_pna`, and the client also launches a **pinned Chromium 140**
(via `playwright==1.55.0`) that navigates there and registers on a
**separate** WebSocket bridge (`/ws_pna`, `BROWSER_PNA_BRIDGE`). Its
`fetch()` deliberately provokes a real OPTIONS preflight (cross-origin +
a non-safelisted header) and rides the guess in the request-URI **path**
(never a body). `scripts/verify_browser_pna.py` uses the attacker's
`/pna_probe` endpoint to assert on the wire that the preflight is blocked
and that the c->s SSH volume scales with the path length.

### Benchmark stack isolation

`scripts/benchmark.py` spawns N independent docker-compose projects via
the `docker-compose.bench.yml` overlay, which:

- Project-scopes every `container_name` using `${COMPOSE_PROJECT_NAME}`.
- Drops host port mappings (`ports: !override []`) -- the benchmark
  script dials each attacker / client directly on their docker-bridge
  IPs, discovered via `docker inspect`. This is the default and works
  under **rootful Docker on Linux**, where bridge IPs are host-routable.
  Under **rootless Docker or Docker Desktop** the bridge IPs are *not*
  host-routable (they live in the engine's netns), so the poll hangs at
  readiness; pass `benchmark.py --host-ports` (or `HOST_PORTS=1` to the
  sweep) to instead publish each stack on a unique `127.0.0.1` port (via
  the `docker-compose.bench-ports.yml` overlay) and dial that. Use a
  smaller `--stacks` there.
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

### browser_pna-specific gotchas

- **The CR/LF wall is the whole scenario.** The guess rides in an OPTIONS
  request-URI path, where `\r`/`\n` cannot appear verbatim and
  percent-encoding changes the wire bytes (killing the LZ77 match). So
  the Redis framing + length + `pw0` + `pw1` are un-leakable; only
  `pw2..pw(n-1)` can be recovered. Do not try to "recover" the length or
  first two bytes through the oracle.
- **Seed only `{length, pw0, pw1}`.** That is the sole sanctioned
  shortcut, confined to exactly the un-leakable bytes. `known_prefix` is
  the seeded `pw0∥pw1` (URL-safe), NOT the CR/LF framing. Seeding past
  `pw1` is an unsanctioned shortcut.
- **Length-bounded, no terminator.** `terminator=b""` (the trailing `\r`
  can't be injected). Recovery stops at `max_length` = tail length. Empty
  bytes is falsy, so `run_attack` neither appends it to the alphabet nor
  matches it -- don't "fix" it to a real byte.
- **Must not disable PNA.** No flag/header/config that disables,
  downgrades, or bypasses PNA/CORS/web security. The client launches
  Chromium with `--enable-features=PrivateNetworkAccessRespectPreflightResults`
  (which *strengthens* PNA) and `--no-sandbox` (container OS sandbox only,
  unrelated to web security). Never add
  `--disable-features=...PrivateNetworkAccess...` or `--disable-web-security`.
- **Disjoint URL-safe pools.** Recovery alphabet (lower+digits), alignment
  pool (`_URL_SAFE_ALIGNMENT_POOL`, uppercase `A..H`), and the
  `url_safe_disjoint` flush/prefill pool (uppercase `I..Z`) are pairwise
  disjoint by construction -- this is what makes the short 2-byte anchor
  safe (a 3-byte candidate run can only match the password site). `%` is
  deliberately excluded (it can absorb the next two bytes on the wire).
- **`guess_prefill_bytes` is SMALL (~2048), not 16384.** The 2-byte anchor
  gives only a 3-byte LZ77 match, which compresses over 3 literals *only
  at a short distance*. A large (16 KiB) prefill pushes the buffered
  secret out of match range -> no signal -> a wrong candidate wins.
  Copying the Firefox 16384 here silently fails. The prefill is drawn
  RANDOMLY (a constant prefill freezes a per-candidate dynamic-Huffman
  bias, since HTTP framing follows the guess so it is not isolated in a
  static block); `outlier_threshold=0` because the random prefill's
  variance would otherwise discard every round.
- **Pinned Chromium is load-bearing.** `playwright==1.55.0` -> Chromium
  140. Pre-142 (no Local Network Access permission prompt, which a
  headless browser would auto-deny). Do not bump without re-validating
  against the sniffer; 141 has a staged LNA rollout, 142 enforces the
  prompt.
- **Two browsers, two bridges.** The client runs Firefox (`/ws`,
  `/exploit`, scenario `browser`) and Chromium (`/ws_pna`,
  `/exploit_pna`, scenario `browser_pna`) side by side; `_build_adapter`
  routes each scenario to its own `BrowserBridge`. The Chromium launch is
  gated by `LAUNCH_CHROMIUM` (default on; `benchmark.py` sets it to `0`
  for runs that don't include `browser_pna`, so non-PNA benchmark stacks
  don't pay for an idle second browser).
- **NO/CE are `n/a`.** Like `browser`, the noise floor mandates an
  alignment sweep, so the fixed-alignment presets don't apply.
- **Ansible `fixed_single` mode is the speed knob, not a correctness
  knob.** After the first position locks the winning alignment length,
  pinning to it skips the 8x sweep. If the sweep fails to lock, the
  trial fails -- don't silently disable the sweep.
- **Sweep harness exit codes.** `scripts/sweep_min_margin.sh` relies on
  `benchmark.py` distinguishing rc=1 (algorithmic miss; bump
  `min_margin` and retry) from rc=2 (technical/infrastructure failure;
  abort entire sweep). Don't muddle the two.
- **`evaluation/` is curated, not raw sweep output.** A fresh
  `scripts/sweep_min_margin.sh` run writes to
  `results/{OPTIMIZATION}/benchmark_*_{scenario}_mmN.{json,csv}`
  (optimization-first). The committed Table-2 dataset is at
  `evaluation/{scenario}/{optimization}/benchmark_*_{scenario}_mmN.{json,csv}`
  (scenario-first). If you re-run the sweep, don't dump straight into
  `evaluation/`: it'll mix layouts and clobber whichever rows the paper
  cites. Land new runs under `results/` and reorganise deliberately.

## File -> purpose quick reference

- `attacker/attack/engine.py` -- round loop, ranking, metrics,
  `run_attack()` coroutine, and `resolve_stalled_position()`
  (fork-on-stall fallback). Transport-agnostic.
- `attacker/attack/config.py` -- `AttackConfig`, `AlignmentMode`,
  `overlay()` for JSON -> dataclass marshalling.
- `attacker/attack/alignment.py` -- `_ALIGNMENT_POOL`, `make_alignment()`.
- `attacker/attack/adapters/{direct,browser,browser_pna,ansible}.py` --
  per-scenario ordering + `default_config()`.
- `attacker/attack/adapters/browser_pna.py` -- PNA sibling of
  `browser.py`; URL-path guess vehicle, URL-safe byte pools, path-builder
  with CR/LF + percent-encode invariants.
- `attacker/exploit_pna.html` -- PNA exploit page (fetch() that provokes
  the OPTIONS preflight; served at `/exploit_pna`).
- `attacker/attack/adapters/browser_bridge.py` -- WebSocket dispatcher
  for the browser adapters; `inject` (body vehicle) and `inject_preflight`
  (URL-path vehicle).
- `attacker/mitm.py` -- container `CMD`; forwarder + sniffer +
  `/run_attack` dispatch; also `/exploit_pna`, `/ws_pna`, and the
  `browser_pna` test-harness diagnostics `/pna_probe` (wire evidence) and
  `/pna_measure` (single measure_once; used to derive the constants).
- `client/client.py` -- SSH subprocess manager, redis-py, Firefox
  launcher (navigates to the attacker-served exploit page), ansible
  runner.
- `scripts/benchmark.py` -- multi-stack scenario harness;
  `OPTIMIZATION_PRESETS` is the single source of truth for the preset
  toggle combinations.
