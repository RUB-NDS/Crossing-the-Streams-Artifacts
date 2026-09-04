# Crossing the Streams: SSH Plaintext Recovery via a Common Compression Context in Multiplexed Channels - Artifacts

This repository accompanies the paper *Crossing the Streams: SSH
Plaintext Recovery via a Common Compression Context in Multiplexed
Channels*. It implements the adaptive compression attack of Section 4
and instantiates it in the three proof-of-concept scenarios of
Section 5:

- **Direct plaintext injection** (Section 5.1) — raw TCP into a
  network-exposed port forward.
- **Browser-based plaintext injection** (Section 5.2) — a
  Playwright-automated headless Firefox injecting into a
  loopback-bound port forward via `navigator.sendBeacon()`.
- **Ansible password recovery** (Section 5.3) — a fresh
  `ansible-playbook` run per guess, recovering the privilege-escalation
  password that Ansible's `become` plugin writes to ssh's stdin.

Refer to the paper for the attacker model, the attack algorithm, the
security analysis, the results, and the discussion. This README only
describes how to reproduce the artifact.


## Requirements

- Docker (with `docker compose`).
- Python 3 on the host. The verify and benchmark scripts use only the
  standard library (`urllib`, `json`).


## Quick start

```bash
# 1. Build the images and bring everything up.
docker compose up -d --build

# 2. Run the per-scenario verifications. Each recovers "hunter2" end-to-end.
python scripts/verify_direct.py     # Section 5.1, ~2 min
python scripts/verify_browser.py    # Section 5.2, ~17 min
python scripts/verify_ansible.py    # Section 5.3, ~4 min

# 3. Watch per-byte progress while an attack is running.
docker compose logs -f attacker
```


## Reproducing Table 3

Table 3 in the paper is produced by `scripts/benchmark.py`, which
spawns N independent docker-compose projects in parallel via
`docker-compose.bench.yml`. A wrapper script,
`scripts/sweep_commit_margin.sh`, sweeps the commit margin `μ`
(`commit_margin` in the code) per (scenario, configuration) in 8-byte
steps until all trials recover the password, allowing up to two retries
per password to absorb transient measurement noise. Outputs land under
`results/{NO,FS,AS,CE,AS+CE}/`, one directory per
noise-compensation configuration of Section 4.3:

| `--compensation` | Noise compensation                                            |
| :--------------- | :------------------------------------------------------------ |
| `NO`             | No further compensation (known winning alignment length).     |
| `FS`             | Full alignment sweep.                                         |
| `AS`             | Adaptive alignment sweep.                                     |
| `CE`             | Candidate elimination (known winning alignment length).       |
| `AS+CE`          | Adaptive alignment sweep combined with candidate elimination. |

`NO` and `CE` fix the alignment length instead of sweeping it, so they
need the winning length passed in with `--alignment-length`.

```bash
# All five configurations, all three scenarios, default 100 trials each.
scripts/sweep_commit_margin.sh

# A single scenario / configuration / commit margin.
python scripts/benchmark.py \
    --stacks 4 --trials 100 \
    --scenarios direct \
    --compensation AS+CE

# A configuration with a known alignment length.
python scripts/benchmark.py \
    --stacks 2 --trials 50 \
    --scenarios ansible \
    --compensation NO --alignment-length 1 --commit-margin 8
```

`scripts/benchmark.py` writes `benchmark_results.json` (per-trial
detail) and `benchmark_summary.csv` (per-`(scenario, configuration)`
aggregates). `scripts/stats.py` prints a mean / median / stdev summary
from a results file. Guess counts include the guesses spent on the
password length byte and the terminator, matching the counts reported
in Table 3.

The results that back Table 3 in the paper are checked in under
`evaluation/`, organised as
`evaluation/{scenario}/{configuration}/benchmark_{results,summary}_{scenario}_cmN.{json,csv}`.
Each directory holds the full commit-margin sweep history that
`scripts/sweep_commit_margin.sh` walked through for that
`(scenario, configuration)` pair — one `(results.json, summary.csv)`
pair per commit-margin step (`cmN`), up to and including the step that
reached 100 % recovery. `evaluation/browser/{no,ce}/` are absent by
design: `NO` and `CE` presuppose a known winning alignment length, and
the browser scenario's noise floor does not support that assumption —
these are the cells marked n/a in Table 3. Run `scripts/stats.py`
against any `benchmark_results_*.json` under `evaluation/` to reproduce
the per-cell summary statistics.

The committed files use the same schema `benchmark.py` writes today, so
`stats.py` and any other consumer sees one shape across `evaluation/`
and fresh `results/` runs. Note the two trees differ only in path
shape: `results/` is compensation-first with uppercase labels
(`results/AS+CE/`), `evaluation/` is scenario-first with lowercase ones
(`evaluation/direct/as+ce/`).


## Repository layout

```
README.md                          — this file
docker-compose.yml                 — five services on the sshpoc bridge
docker-compose.bench.yml           — overlay for N parallel benchmark stacks
keys/                              — Ed25519 host + client keys (generated)
evaluation/                        — Table 3 sweep outputs, one tree per
                                     (scenario, configuration), one file
                                     pair per commit-margin step
scripts/
    keygen.sh                      — one-shot ssh-keygen wrapper
    pin-hosts.sh                   — /etc/hosts pinning at container start
    verify_direct.py               — preconditions + hunter2 (direct)
    verify_browser.py              — preconditions + hunter2 (browser)
    verify_ansible.py              — preconditions + hunter2 (ansible)
    benchmark.py                   — multi-stack scenario benchmark
    sweep_commit_margin.sh         — commit-margin sweep harness
    stats.py                       — summary stats over a results JSON
server/                            — debian:bookworm-slim + openssh-server
    Dockerfile
    sshd_config
    entrypoint.sh
client/                            — python:3.14 + openssh-client + Firefox
    Dockerfile
    client.py
    requirements.txt
    ansible/                       — inventory + playbook + ansible.cfg
attacker/
    Dockerfile
    requirements.txt
    mitm.py                        — TCP forwarder + sniffer + /run_attack
    exploit.html                   — browser-injection exploit page
    attack/                        — attack engine package
        engine.py                  — run_attack, crack_byte_position,
                                     resolve_stalled_position
        config.py                  — AttackConfig, AlignmentMode
        alignment.py               — _ALIGNMENT_POOL, make_alignment
        adapters/
            base.py                — Adapter Protocol
            direct.py              — raw-TCP injection
            browser.py             — browser sendBeacon injection
            ansible.py             — fresh-SSH-per-guess injection
            browser_bridge.py      — WebSocket bridge for browser scenario
        tests/                     — plain-assertion sanity tests
```


## Architecture

Five long-lived containers plus a one-shot keygen, all on a single
Docker bridge network (`sshpoc`):

- **`poc-keygen`** — generates an Ed25519 host key and a client user
  key.
- **`poc-redis`** — official Redis 8. The client sets the AUTH
  password via `CONFIG SET requirepass` after the SSH tunnel is up.
- **`poc-server`** — OpenSSH server with `Compression yes` and
  `AllowTcpForwarding yes`.
- **`poc-client`** — the victim host. Runs an OpenSSH subprocess with
  two local port forwards, redis-py, a headless Firefox via
  Playwright (browser scenario), and `ansible-playbook` on demand.
  Exposes an aiohttp HTTP control API on port 8000.
- **`poc-attacker`** — three jobs in one process: a passive TCP
  forwarder between the client (`:2222`) and the server (`:22`); a
  Scapy `AsyncSniffer` on `eth0` with the BPF filter
  `tcp and (port 22 or port 2222)`; and an aiohttp HTTP control API
  on port 9000 (notably `/run_attack`, the unified attack endpoint
  that dispatches to the per-scenario adapter).

The client connects to the attacker on `:2222` but pins the **real**
server's host key in `known_hosts`. The attacker is a passive on-path
observer: it never terminates, decrypts, or modifies SSH; any active
in-the-middle attempt would be detected at the SSH layer.


## HTTP control surface

### Client (`http://localhost:8000`)

| Method | Path                   | Description                                                                                                  |
| :----- | :--------------------- | :----------------------------------------------------------------------------------------------------------- |
| GET    | `/status`              | SSH state, negotiated algorithms, port-forward state, browser state.                                         |
| POST   | `/send_secret`         | Opens a fresh redis-py connection through the tunnel; `AUTH default <password>` hits the wire.               |
| POST   | `/set_secret`          | `{"value": "..."}` — reconfigures the Redis password and reconnects SSH.                                     |
| POST   | `/reset`               | Tear down and re-open the SSH connection.                                                                    |
| POST   | `/send_secret_ansible` | Kick off a fresh `ansible-playbook` run; returns when the sudo password has been written to ssh's stdin.     |
| POST   | `/set_sudo_secret`     | `{"value": "..."}` — rotates the sudo password via a root SSH login.                                         |

### Attacker (`http://localhost:9000`)

| Method | Path               | Description                                                                                  |
| :----- | :----------------- | :------------------------------------------------------------------------------------------- |
| GET    | `/status`          | Forwarder + sniffer state + browser-bridge state.                                            |
| GET    | `/packet_log`      | Scapy-captured TCP segments since the last clear.                                            |
| POST   | `/clear_log`       | Reset the packet log.                                                                        |
| POST   | `/trigger_secret`  | Convenience: proxies to client `/send_secret`.                                               |
| POST   | `/trigger_payload` | Writes a raw payload through the client's Redis tunnel.                                      |
| GET    | `/exploit`         | Serves the browser-injection exploit page.                                                   |
| GET    | `/ws`              | WebSocket endpoint for the victim's browser.                                                 |
| POST   | `/run_attack`      | Unified attack endpoint — dispatches on `scenario`.                                          |
| POST   | `/cancel`          | Set the cancel-event so an in-flight `/run_attack` returns at the next position boundary.    |

`/run_attack` request body (all `config` fields are optional; omitted
fields fall back to the adapter's `default_config()`):

```json
{
  "scenario": "direct | browser | ansible",
  "config": {
    "known_prefix":             "...",
    "alphabet":                 "abcdefghijklmnopqrstuvwxyz0123456789",
    "max_length":               32,
    "terminator":               "\r",
    "commit_margin":             16,
    "max_rounds":                64,
    "alignment_mode":            "full_sweep",
    "alignment_lengths":         [0, 1, 2, 3, 4, 5, 6, 7],
    "candidate_elimination":     true,
    "adaptive_alignment_sweep":  true,
    "alignment_reintroduction":  true,
    "alignment_carryover":       true,
    "constant_prefix_trim":      true
  },
  "expected": "hunter2\r"
}
```

`expected`, when supplied, is the ground-truth byte stream. The engine
compares each committed byte against `expected[N]` and aborts with
`abort_reason: "mismatch"` on the first divergence;
`benchmark.py --early-exit` uses this to fast-fail doomed runs.

The response includes `recovered`, `total_guesses`, `elapsed_seconds`,
and a `per_position` array with each position's `final_margin`,
`successful_alignment`, ranked candidate sums, and clean-commit flag.

How the config keys map onto the paper:

| Config key                 | Paper                                                                        |
| :------------------------- | :--------------------------------------------------------------------------- |
| `known_prefix`             | The known prefix `p` of Algorithm 2.                                         |
| `commit_margin`            | The commit margin `μ` (Section 4.2).                                         |
| `alignment_lengths`        | The alignment lengths `ℓ` swept over (Section 4.3).                          |
| `alignment_mode`           | `full_sweep` = full alignment sweep; `known_length` = the attacker knows `ℓ`. |
| `candidate_elimination`    | Candidate elimination (Section 4.3).                                         |
| `adaptive_alignment_sweep` | Pruning of unproductive alignment lengths (adaptive alignment sweep, Section 4.3). |
| `alignment_reintroduction` | Reintroducing pruned alignment lengths after two rounds without an observable difference. |
| `alignment_carryover`      | Carrying the pruned set over between byte positions.                         |
| `flush_bytes`              | Size of the LZ77 search-buffer flush (Section 4.2).                          |
| `guess_prefill_bytes`      | Random data prepended to the guess body to force a static Huffman block, browser scenario only (Section 5.2). |

`constant_prefix_trim`, `outlier_threshold`, and
`candidate_fork_on_stall` have no counterpart in the paper.


## Engine + adapter split

`attacker/attack/engine.py` runs the round loop, the candidate
ranking, the alignment sweep, the noise-compensation strategies of
Section 4.3, and the per-position metrics.
Transport-specific ordering (flush / open measure channel / trigger
secret / send guess / read packet log) lives in
`attacker/attack/adapters/{direct,browser,ansible}.py`. The engine
calls a single method on its adapter:

```python
async def measure_once(prefix, candidate, alignment) -> int  # wire-byte count
```

`AttackConfig.overlay()` (in `attacker/attack/config.py`) marshals
JSON overrides on top of an adapter-supplied `default_config()`.


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
`scripts/verify_*.py` scripts — a successful recovery is the test.


## Editing notes

- `attacker/` and `client/` sources are `COPY`'d into the images at
  build time, not bind-mounted: rebuild the relevant service after
  edits (`docker compose build attacker && docker compose up -d attacker`).
- The alignment-data pool (`0x80..0x8F`), the per-scenario
  `commit_margin`, `flush_bytes=32768` (deflate's maximum search-buffer
  size), `guess_prefill_bytes=16384` (browser scenario only), and the
  adapter-specific ordering all decide whether the attack works at
  all. They are explained in Sections 4 and 5 of the paper and in the
  adapter docstrings. `outlier_threshold`, `constant_prefix_trim`, and
  `candidate_fork_on_stall` are implementation details with no
  counterpart in the paper; the latter is off in every configuration
  and therefore not exercised by the Table 3 runs.
- The 8-byte alignment sweep (`alignment_lengths=[0..7]`) assumes
  ChaCha20-Poly1305's padding granularity. AES-based modes pad to 16
  bytes and would require `[0..15]`, growing the sweep — and with it
  the guess count — linearly (cf. Section 8.1). The negotiated cipher
  is visible at `GET http://localhost:8000/status`.


## Generative AI usage

The proof-of-concept implementations for each of the three attack
scenarios presented in Section 5 of the paper were implemented with
the help of Claude Code. We provided Claude Code with the description
of the generic attack, the assumed attacker model, descriptions for
the different scenarios, and an explicit requirement to avoid
shortcuts in its implementation. After implementation, we performed a
manual code review to ensure that the attacker model and the
implementation of each scenario are accurate and that no unexpected
shortcuts were taken. Correctness was verified by dedicated
integration tests that recover passwords end-to-end. This, alongside
our manual code review, ensures that the reported figures in Table 3
are accurate.
