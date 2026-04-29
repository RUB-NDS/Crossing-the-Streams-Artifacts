# Adaptive compression attack on SSH -- PoC artifact

This repository accompanies the paper *Crossing the Streams: SSH Plaintext
Recovery via a Common Compression Context in Multiplexed Channels*. It
implements the adaptive compression attack of Section 4 and instantiates
it in the three proof-of-concept scenarios of Section 5:

- **Direct injection** (Section 5.1) -- raw TCP into an exposed port forward.
- **Browser-based injection** (Section 5.2) -- `navigator.sendBeacon()`
  from a headless Firefox to a loopback-bound port forward.
- **Ansible password recovery** (Section 5.3) -- a fresh
  `ansible-playbook` run per guess, recovering the sudo password sent via
  `become: yes`.

Refer to the paper for the threat model, attack algorithm, security
analysis, results, and discussion. This README only describes how to
reproduce the artifact.

## Requirements

- Docker (with `docker compose`).
- Python 3 on the host. The verify and benchmark scripts use only the
  standard library (`urllib`, `json`).

## Quick start

```bash
# 1. Build images and bring everything up.
docker compose up -d --build

# 2. Run the per-variant verifications. Each recovers "hunter2" end-to-end.
python scripts/verify_direct.py     # Section 5.1, ~2 min
python scripts/verify_browser.py    # Section 5.2, ~17 min
python scripts/verify_ansible.py    # Section 5.3, ~4 min

# 3. Watch per-byte progress while an attack is running.
docker compose logs -f attacker
```

## Reproducing Table 2

The five-row × three-variant guess-count table in the paper is produced
by `scripts/benchmark.py`, which spawns N independent docker-compose
projects in parallel via `docker-compose.bench.yml`. A wrapper script,
`scripts/sweep_min_margin.sh`, sweeps the commit margin (`min_margin`,
i.e. `μ` in the paper) per (variant, scenario) until 100 % recovery is
reached. Outputs land under `results/{baseline,sweep,adaptive,elim,full}/`.

```bash
# All five scenarios, all three variants, default 100 trials each.
scripts/sweep_min_margin.sh

# Single scenario / variant / commit margin.
python scripts/benchmark.py \
    --stacks 4 --trials 100 \
    --variants direct \
    --scenario all-opts
```

`scripts/benchmark.py` writes `benchmark_results.json` (per-trial detail)
and `benchmark_summary.csv` (per-`(variant, scenario)` aggregates).
`scripts/stats.py` prints a mean / median / stdev summary from a results
file.

## Repository layout

```
README.md                                  -- this file
docker-compose.yml                         -- five services on the sshpoc bridge
docker-compose.bench.yml                   -- overlay for N parallel benchmark stacks
keys/                                      -- ed25519 host + client keys (generated)
scripts/
    keygen.sh                              -- one-shot ssh-keygen wrapper
    pin-hosts.sh                           -- /etc/hosts pinning at container start
    verify_direct.py                       -- preconditions + hunter2 (direct)
    verify_browser.py                      -- preconditions + hunter2 (browser)
    verify_ansible.py                      -- preconditions + hunter2 (ansible)
    benchmark.py                           -- multi-stack scenario benchmark
    sweep_min_margin.sh                    -- commit-margin sweep harness
    stats.py                               -- summary stats over a results JSON
server/                                    -- debian:bookworm-slim + openssh-server
    Dockerfile, sshd_config, entrypoint.sh
client/                                    -- python:3.14 + openssh-client + Firefox
    Dockerfile, client.py, requirements.txt
    ansible/                               -- inventory + playbook + ansible.cfg
attacker/
    Dockerfile, requirements.txt
    mitm.py                                -- TCP forwarder + sniffer + /run_attack
    exploit.html                           -- browser-injection exploit page
    attack/                                -- attack engine package
        engine.py                          -- run_attack, crack_byte_position
        config.py                          -- AttackConfig, AlignmentMode
        alignment.py                       -- _ALIGNMENT_POOL, make_alignment
        adapters/
            base.py                        -- Adapter Protocol
            direct.py                      -- raw-TCP injection
            browser.py                     -- browser sendBeacon injection
            ansible.py                     -- fresh-SSH-per-guess injection
            browser_bridge.py              -- WebSocket bridge for browser variant
        tests/                             -- plain-assertion sanity tests
```

## Architecture

Five long-lived containers plus a one-shot keygen, all on a single Docker
bridge network (`sshpoc`):

- `poc-keygen` -- generates an Ed25519 host key and a client user key.
- `poc-redis` -- official Redis 8. The client sets the AUTH password
  via `CONFIG SET requirepass` after the SSH tunnel is up.
- `poc-server` -- OpenSSH server with `Compression yes` and
  `AllowTcpForwarding yes`.
- `poc-client` -- the victim host. Runs an OpenSSH subprocess with two
  local port forwards, redis-py, headless Firefox via Playwright (browser
  variant), and `ansible-playbook` on demand. Exposes an aiohttp HTTP
  control API on port 8000.
- `poc-attacker` -- three jobs in one process: a passive TCP forwarder
  between client (`:2222`) and server (`:22`); a scapy `AsyncSniffer` on
  `eth0` with BPF filter `tcp and (port 22 or port 2222)`; and an aiohttp
  HTTP control API on port 9000 (notably `/run_attack`, the unified
  attack endpoint that dispatches to the per-variant adapter).

The client connects to the attacker on `:2222` but pins the **real**
server's host key in `known_hosts`. The attacker is a passive on-path
observer: it never terminates, decrypts, or modifies SSH; any active
in-the-middle attempt would be detected at the SSH layer.

## HTTP control surface

### Client (`http://localhost:8000`)

| Method | Path                     | Description |
|--------|--------------------------|-------------|
| GET    | `/status`                | SSH state, negotiated algorithms, port-forward state, browser state |
| POST   | `/send_secret`           | Opens a fresh redis-py connection through the tunnel; AUTH default \<password\> hits the wire |
| POST   | `/set_secret`            | `{"value": "..."}` -- reconfigures the Redis password and reconnects SSH |
| POST   | `/reset`                 | Tear down and re-open the SSH connection |
| POST   | `/send_secret_ansible`   | Kick off a fresh `ansible-playbook` run; returns when the sudo password has been written to ssh's stdin |
| POST   | `/set_sudo_secret`       | `{"value": "..."}` -- rotates the sudo password via a root SSH login |

### Attacker (`http://localhost:9000`)

| Method | Path               | Description |
|--------|--------------------|-------------|
| GET    | `/status`          | Forwarder + sniffer state + browser-bridge state |
| GET    | `/packet_log`      | scapy-captured TCP segments since the last clear |
| POST   | `/clear_log`       | Reset the packet log |
| POST   | `/trigger_secret`  | Convenience: proxies to client `/send_secret` |
| POST   | `/trigger_payload` | Writes a raw payload through the client's Redis tunnel |
| GET    | `/exploit`         | Serves the browser-injection exploit page |
| GET    | `/ws`              | WebSocket endpoint for the victim's browser |
| POST   | `/run_attack`      | Unified attack endpoint -- dispatches on `variant` |
| POST   | `/cancel`          | Set the cancel-event so an in-flight `/run_attack` returns at the next position boundary |

`/run_attack` request body (all `config` fields optional; omitted fields
fall back to the adapter's `default_config()`):

```json
{
  "variant": "direct | browser | ansible",
  "config": {
    "known_prefix":        "...",
    "alphabet":            "abcdefghijklmnopqrstuvwxyz0123456789",
    "max_length":          32,
    "terminator":          "\r",
    "min_margin":          16,
    "max_rounds":          64,
    "alignment_mode":      "full_sweep",
    "alignment_lengths":   [0,1,2,3,4,5,6,7],
    "candidate_elimination":    true,
    "constant_prefix_trim":     true,
    "adaptive_alignment":       true,
    "stall_detection":          true,
    "alignment_hint_carryover": true
  },
  "expected": "hunter2\r"
}
```

`expected`, when supplied, is the ground-truth byte stream. The engine
compares each committed byte against `expected[N]` and aborts with
`abort_reason: "mismatch"` on the first divergence. `benchmark.py
--early-exit` uses this to fast-fail doomed runs.

The response includes `recovered`, `total_guesses`, `elapsed_seconds`,
and a `per_position` array with each position's `final_margin`,
`successful_alignment`, ranked candidate sums, and clean-commit flag.

## Engine + adapter split

`attacker/attack/engine.py` runs the round loop, candidate ranking,
alignment sweep, and per-position metrics. Transport-specific ordering
(flush / open measure channel / trigger secret / send guess / read packet
log) lives in `attacker/attack/adapters/{direct,browser,ansible}.py`.
The engine calls a single method on its adapter:

```python
async def measure_once(prefix, candidate, alignment) -> int  # wire-byte count
```

`AttackConfig.overlay()` (in `attacker/attack/config.py`) marshals JSON
overrides on top of an adapter-supplied `default_config()`.

## Tests

```bash
python -m attacker.attack.tests.test_engine_helpers
python -m attacker.attack.tests.test_engine_expected
python -m attacker.attack.tests.test_alignment
python -m attacker.attack.tests.test_config
python -m attacker.attack.tests.test_fork
```

These are pure-logic unit tests that run on the host without the
docker-compose stack. End-to-end correctness is verified by the
`scripts/verify_*.py` scripts -- a successful recovery is the test.

## Editing notes

- `attacker/` and `client/` sources are `COPY`'d into the images at build
  time, not bind-mounted: rebuild the relevant service after edits
  (`docker compose build attacker && docker compose up -d attacker`).
- The alignment-data pool (`0x80..0x8F`), per-variant `min_margin`,
  `flush_bytes=33000`, `guess_prefill_bytes=16384` (browser only), and
  the adapter-specific ordering are load-bearing. They are documented
  in the paper (Sections 4, 5) and in adapter docstrings.
- The 8-byte alignment sweep (`alignment_lengths=[0..7]`) assumes
  ChaCha20-Poly1305's padding granularity. AES-CTR+HMAC-ETM would
  require `[0..15]`. The negotiated cipher is visible at `GET
  http://localhost:8000/status`.
