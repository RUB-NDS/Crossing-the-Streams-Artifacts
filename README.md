# Crossing the Streams: SSH Plaintext Recovery via a Common Compression Context in Multiplexed Channels - Artifacts

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22308155.svg)](https://doi.org/10.5281/zenodo.22308155)

This repository contains the artifacts for *Crossing the Streams: SSH
Plaintext Recovery via a Common Compression Context in Multiplexed
Channels*. The artifacts implement the adaptive compression attack in
Section 4 for the three scenarios in Section 5 and include the raw
measurements for Table 3. They are licensed under [Apache-2.0](LICENSE).

The evaluation workflow below uses the same claims (C1–C4) and experiments
(E1–E4) as the artifact appendix. E1–E3 verify password recovery in the
three scenarios. E4 computes the statistics in Table 3 from the included
data; collecting new measurements is optional. Section and figure
references refer to the paper.

- [Description & Requirements](#description--requirements)
- [Set Up](#set-up)
- [Evaluation Workflow](#evaluation-workflow)
- [Troubleshooting](#troubleshooting)
- [Repository Layout](#repository-layout)
- [Architecture](#architecture)
- [HTTP Control API](#http-control-api)
- [Notes on Reusability](#notes-on-reusability)
- [Generative AI Usage](#generative-ai-usage)

## Description & Requirements

The testbed consists of five Docker Compose services: key generation,
SSH server, Redis, victim client, and attacker. Python scripts on the host
run the experiments and analyze the results. The [repository layout](#repository-layout)
and [architecture](#architecture) sections describe the components.

### How to Access

Version 2 is archived on [Zenodo](https://doi.org/10.5281/zenodo.22308155).
The development repository is
[GitHub](https://github.com/RUB-NDS/Crossing-the-Streams-Artifacts), with
release tag `v2` corresponding to the archive.

### Hardware Requirements

No specialized hardware is required. For E1–E3, we recommend an x86-64
Linux host with at least 4 cores, 8 GB of RAM, and 5 GB of free disk space
for the container images. E4 uses the included measurements and requires
only a host with Python 3.

The original Table 3 measurements used 100 parallel Compose projects
(400 running containers) on a dual-socket AMD EPYC 7763 system with 2 TB
of RAM running Ubuntu 22.04. This system is not required for artifact
evaluation. For optional new measurements, reduce `--stacks` to fit the
available hardware, including `--stacks 1` for sequential trials. Fewer
stacks reduce resource requirements and increase execution time.

### Software Requirements

- Linux and Docker Engine with the Compose plugin for E1–E3 and optional
  new measurements in E4.
- Python 3 on the host. The verification, benchmark, and statistics
  scripts use only the standard library.
- `curl` for the status checks below, and Bash for the optional sweep
  script and the loop that analyzes all Table 3 configurations.
- Internet access to download dependencies when building the images.

The parallel benchmark runs used Ubuntu 22.04. The host tool versions
reported for the evaluation are Docker 29.8, Compose v5.5, and Python
3.14. Container builds install the remaining dependencies, including
`aiohttp`, Scapy, redis-py, Playwright with headless Firefox, and
`ansible-core`. Python package versions are pinned in the requirements
files. The base images are `python:3.14-slim`, `debian:bookworm-slim`, and
`redis:8-alpine`.

### Security, Privacy, and Ethical Concerns

The experiments perform plaintext recovery within a Docker bridge
network on the evaluator's host. They use generated SSH keys and
synthetic passwords: either `hunter2` or values from a seeded
pseudorandom number generator. No external targets or real credentials
are required. SSH keys are generated in `keys/`.

The attacker container receives the `NET_ADMIN` and `NET_RAW`
capabilities for packet capture. The default Compose configuration
publishes the client and attacker control APIs on host ports 8000 and
9000. These APIs are unauthenticated and can initiate attacks and inject
data into the victim's tunnel. Restrict access to these ports to trusted
hosts.

### Benchmarks and Data

No external dataset is required. `evaluation/` contains the measurements
for Table 3, organized by scenario and configuration. The benchmark
creates 8-character lowercase passwords using a configurable random seed.
The original measurements used seed 42 for direct and browser injection
and seed 4253 for Ansible. [E4](#e4-table-3) identifies the files and
parameters corresponding to the reported results.

## Set Up

All commands below are run from the repository root. If Python 3 is
available as `python3` on the host, use that command in place of `python`.
For E4 with the included data, skip the Docker installation and testbed
checks and proceed directly to [E4](#e4-table-3).

### Installation

Clone the repository or extract the Zenodo archive. Ensure that host
ports 8000 and 9000 are available, then build and start the testbed:

```bash
docker compose up -d --build
```

The build takes several minutes, including the Firefox download. Check
service state with:

```bash
docker compose ps -a
```

`poc-keygen` should have exited with code 0. The other four services
(`poc-server`, `poc-redis`, `poc-client`, and `poc-attacker`) should be
running.

### Basic Functionality Test

The engine's unit tests run on the host without Docker:

```bash
python -m attacker.attack.tests.test_config
python -m attacker.attack.tests.test_engine_helpers
python -m attacker.attack.tests.test_engine_expected
python -m attacker.attack.tests.test_alignment
python -m attacker.attack.tests.test_fork
```

Each command prints a line ending in `ok` and exits with code 0.

Check the running testbed through its control APIs:

```bash
curl -s localhost:8000/status
curl -s localhost:9000/status
```

The client should report `ssh_connected: true`, zlib compression in both
directions, and an active `redis_tunnel`. The attacker should report the
forwarding target, capture interface, and BPF filter. Both APIs should
report `browser_connected: true`; the browser connects shortly after the
client starts.

## Evaluation Workflow

### Major Claims

- **(C1): Direct plaintext injection (Section 5.1, Fig. 3).** A network
  attacker with access to a forwarded TCP port can recover a secret
  transmitted over another channel of the same SSH connection by
  injecting chosen plaintext and observing ciphertext lengths.
  Evaluated by [E1](#e1-direct-plaintext-injection).
- **(C2): Browser-based plaintext injection (Section 5.2, Fig. 4).**
  Under the combined eavesdropper and web attacker model, JavaScript in
  the victim's browser can inject guesses into a loopback-bound port
  forward to recover the secret. Evaluated by
  [E2](#e2-browser-based-plaintext-injection).
- **(C3): Ansible password recovery (Section 5.3, Fig. 5).** The attack
  also recovers Ansible's `become` password, which is transmitted through
  a session channel. Evaluated by [E3](#e3-ansible-password-recovery).
- **(C4): Guess counts (Section 5.4, Table 3).** Table 3 reports guess
  counts for recovering 8-character lowercase passwords across three
  scenarios and five noise-compensation configurations. All 100 trials
  per evaluated combination succeeded at the reported commit margins,
  with up to two retries per password. Evaluated by [E4](#e4-table-3),
  excluding the two combinations marked `n/a`.

### Expected Results

Times are estimates and exclude the initial image build. E1–E3 each
require about 2 person-minutes; E4 requires about 15 person-minutes to
analyze the included data.

| Experiment | Claim | Expected result | Approximate compute time |
| :--- | :--- | :--- | :--- |
| [E1: Direct injection](#e1-direct-plaintext-injection) | C1 | Recover `hunter2`; `VERIFICATION PASSED`; exit code 0 | 2 minutes |
| [E2: Browser injection](#e2-browser-based-plaintext-injection) | C2 | Recover `hunter2`; `Status: PASS`; exit code 0 | 17 minutes |
| [E3: Ansible](#e3-ansible-password-recovery) | C3 | Recover `hunter2`; `Status: PASS`; exit code 0 | 4 minutes |
| [E4: Table 3](#e4-table-3) | C4 | Statistics match Table 3; `n` is 100 for each of the 13 evaluated combinations | 1 minute using included data |

### Running, Monitoring, and Restarting Attacks

**Only one attack may run at a time in each testbed. Run E1–E3
sequentially, in any order; do not run the three verification scripts
concurrently.** Wait for one script to finish before starting another.
The benchmark harness uses separate testbeds to run trials in parallel.

In a separate terminal, track candidate margins and progress for each
recovered byte:

```bash
docker compose logs -f attacker
```

For optional parallel benchmarks, inspect an individual attacker
container. With the default `bench` prefix, the first stack is:

```bash
docker logs -f bench-0-attacker
```

Before restarting or retrying a verification attack, stop its host script
if it is still running, then recreate the testbed:

```bash
docker compose down
docker compose up -d
```

Wait for the [basic functionality checks](#basic-functionality-test) to
pass before starting the script again. Stopping the host script alone
does not ensure that the attack inside the container has stopped.
After evaluation, stop the verification testbed with `docker compose down`.

### Experiments

#### E1: Direct Plaintext Injection

**Claim:** C1. **Time:** 2 person-minutes + approximately 2 compute-minutes.

**Preparation:** Complete [Set Up](#set-up) and confirm that no other
verification script is running.

**Execution:**

```bash
python scripts/verify_direct.py
```

**Results:** The script checks API availability, SSH compression, the
Redis tunnel, and packet capture. It injects guesses into the forwarded
TCP port and recovers the password from a Redis authentication request,
first determining its length and then its contents. It prints the
recovered password, guess counts, and elapsed time. A successful run
recovers `hunter2`, prints `VERIFICATION PASSED`, and exits with code 0.
An incorrect password causes exit code 1. For noisy failures, follow
[Troubleshooting](#troubleshooting).

#### E2: Browser-Based Plaintext Injection

**Claim:** C2. **Time:** 2 person-minutes + approximately 17 compute-minutes.

**Preparation:** Complete [Set Up](#set-up). Confirm that the attacker
status reports `browser_connected: true` and no other verification
script is running.

**Execution:**

```bash
python scripts/verify_browser.py
```

**Results:** The script checks the prerequisites of E1 and the browser's
WebSocket control channel. The attacker's page in the victim's headless
Firefox injects guesses into a loopback-bound port forward using
`navigator.sendBeacon()`. The script recovers the Redis password length
and contents, prints `hunter2` and `Status: PASS`, and exits with code 0
on success. HTTP framing introduces additional measurement noise,
addressed by an alignment sweep and a higher commit margin. For noisy
failures, follow [Troubleshooting](#troubleshooting).

#### E3: Ansible Password Recovery

**Claim:** C3. **Time:** 2 person-minutes + approximately 4 compute-minutes.

**Preparation:** Complete [Set Up](#set-up) and confirm that no other
verification script is running.

**Execution:**

```bash
python scripts/verify_ansible.py
```

**Results:** The script checks the `LocalForward` configuration, sets the
sudo password, and verifies that Ansible writes it to the SSH client's
standard input. Each guess uses a new `ansible-playbook` execution. The
attack recovers the length byte in the channel-data header and then the
password. Success is indicated by the recovered password `hunter2`,
`Status: PASS`, and exit code 0. For noisy failures, follow
[Troubleshooting](#troubleshooting).

#### E4: Table 3

**Claim:** C4. **Time:** 15 person-minutes + approximately 1 compute-minute
for the included data.

**Preparation:** Only Python 3 and the included `evaluation/` files are
required to compute the reported statistics. No containers are needed.

**Execution:** Run `scripts/stats.py` on each file at the commit margin
reported in Table 3. For example, Ansible with no further compensation:

```bash
python scripts/stats.py evaluation/ansible/no/benchmark_results_ansible_cm8.json
```

The configurations correspond to the strategies in Section 4.3:

| Configuration | Directory name | Noise compensation | Direct margin | Browser margin | Ansible margin |
| :--- | :--- | :--- | ---: | ---: | ---: |
| NO | `no` | No further compensation; known winning alignment length | 8 | n/a | 8 |
| FS | `fs` | Full alignment sweep | 40 | 48 | 8 |
| AS | `as` | Adaptive alignment sweep | 16 | 64 | 8 |
| CE | `ce` | Candidate elimination; known winning alignment length | 16 | n/a | 8 |
| AS+CE | `as+ce` | Adaptive alignment sweep and candidate elimination | 80 | 88 | 8 |

To analyze all 13 combinations, run this Bash loop:

```bash
while read -r scenario config margin; do
    printf '\n%s / %s / margin %s\n' "$scenario" "$config" "$margin"
    python scripts/stats.py \
        "evaluation/$scenario/$config/benchmark_results_${scenario}_cm${margin}.json"
done <<'CELLS'
direct no 8
direct fs 40
direct as 16
direct ce 16
direct as+ce 80
browser fs 48
browser as 64
browser as+ce 88
ansible no 8
ansible fs 8
ansible as 8
ansible ce 8
ansible as+ce 8
CELLS
```

**Results:** Each invocation prints `n`, minimum, maximum, mean, median,
and standard deviation of the guess counts for successful trials. These
values match the corresponding column in Table 3. For example, Ansible
under NO produces:

```text
n      : 100
min    : 276
max    : 474
mean   : 284.0
median : 276.0
stdev  : 35.8
```

Each selected file contains 100 trials and reports `n: 100`, confirming
recovery for every password under the recorded retry policy. Guess
counts include recovery of the password length and terminator. The
browser NO and CE combinations are absent because they require a known
winning alignment length, which the browser scenario's noise floor does
not support. Other files in each directory contain earlier sweep steps
at lower commit margins.

##### Optional: Collect New Measurements

Build the images and generate the SSH keys using [Installation](#installation)
first. The benchmark creates independent Compose projects using
`docker-compose.bench.yml` and removes them when it finishes. To measure
Ansible under NO with 100 passwords and up to two retries per password:

```bash
python scripts/benchmark.py --stacks 4 \
    --trials 100 --scenarios ansible \
    --compensation NO --alignment-length 1 \
    --commit-margin 8 --seed 4253 \
    --max-retries 2
```

Reduce `--stacks` to fit the available resources. For another Table 3
combination, set `--scenarios`, `--compensation`, and `--commit-margin`
according to the table above. Use `--seed 42` for direct and browser
injection and `--seed 4253` for Ansible. NO and CE require
`--alignment-length 2` for direct injection or `--alignment-length 1`
for Ansible; omit this option for the sweep configurations.

The benchmark writes `benchmark_results.json` with per-trial results
and `benchmark_summary.csv` with aggregates. Use `--output` and
`--csv-summary` to select other filenames when retaining multiple runs.
Analyze the JSON file with:

```bash
python scripts/stats.py benchmark_results.json
```

The benchmark exits with code 0 if all trials succeed, 1 for recovery
failures, and 2 for an infrastructure failure. New measurements are
expected to recover all 100 passwords and produce comparable guess
counts and relative performance across configurations. Exact counts can
vary with measurement noise. Record any configuration changes made
while troubleshooting.

Measuring all 13 combinations at the reported margins took approximately
23 hours with 100 parallel stacks on the system described under
[Hardware Requirements](#hardware-requirements). Individual combinations
ranged from 11 minutes (Ansible, NO) to 6 hours (browser, FS). These times
exclude the additional sweep steps used to select the margins.

To search for suitable margins automatically, use the sweep script:

```bash
STACKS=4 scripts/sweep_commit_margin.sh
```

It starts at margin 8, increases the margin in steps of 8 up to 128, and
stops for each scenario/configuration when all 100 passwords are
recovered, allowing up to two retries per password. It skips browser NO
and CE. `STACKS` controls parallelism; the script's default is 20. Other
controls are documented at the start of the script.

The current sweep script uses the benchmark's default seed 4253 for all
scenarios. To use the original direct/browser password sets, run
`benchmark.py` with `--seed 42` as described above. Sweep outputs are
stored under `results/{NO,FS,AS,CE,AS+CE}/`, while the included data use
`evaluation/<scenario>/<lowercase-configuration>/`. Both use the same
JSON schema.

## Troubleshooting

### Failed or Interrupted Runs

If a verification script's prerequisite checks pass but password recovery
fails, measurement noise may be responsible. Recreate the testbed with
`docker compose down` followed by `docker compose up -d`, wait for the
[basic functionality checks](#basic-functionality-test), and retry the
script. Use the same procedure after interruption or timeout. Only one
verification script may use the testbed at a time.

If prerequisites fail, first inspect `docker compose ps -a` and the
client/attacker logs. Confirm that SSH compression, the required port
forward, packet capture, and (for E2) the browser connection are active.
Increasing the commit margin does not resolve a missing connection or
unavailable service.

### Repeated Recovery Failures

Edit the `config` dictionary sent to `/run_attack` in the relevant host
script. Direct and browser verification inherit defaults from their
adapters, so add the desired keys to their existing dictionaries. Ansible
sets several keys explicitly in each phase; update both dictionaries.

| Script | Configuration location |
| :--- | :--- |
| `scripts/verify_direct.py` | `_run_attack()` |
| `scripts/verify_browser.py` | `browser_attack()` |
| `scripts/verify_ansible.py` | `phase1_body` and `phase2_body` |

Changes to these host scripts do not require rebuilding the images.
The relevant parameters and their current verification values are:

| Parameter | Direct | Browser | Ansible | Adjustment |
| :--- | ---: | ---: | ---: | :--- |
| `commit_margin` | 16 | 64 | 8 | Increase in steps of 8 when recovery repeatedly selects incorrect bytes. |
| `max_rounds` | 128 | 128 | 96 | Increase, for example double it, if logs report exhausted rounds before reaching the margin. |
| `settle` | 0.01 | 0.05 | 0.25 | Delay in seconds between measurement steps. If packet capture appears delayed under load, try doubling it. |

`commit_margin` is the minimum difference required to select a candidate
byte. Increasing it requires more measurements; increase `max_rounds`
when the existing limit prevents reaching the new margin. For example,
to raise the direct verification margin from 16 to 24, add these entries
to the existing `config` dictionary in `_run_attack()`:

```python
"commit_margin": 24,
"max_rounds": 256,
```

If Ansible's fixed alignment produces no distinguishing signal, replace
the alignment settings in both phases with:

```python
"alignment_mode": "full_sweep",
"alignment_lengths": list(range(8)),
```

These changes can increase both runtime and guess counts. Recreate the
testbed before retrying, and report adjusted settings with the results.
The [configuration reference](#http-control-api) describes additional
controls and their relation to the paper.

### HTTP Timeouts

If the host script times out while the attacker logs still show progress,
increase the HTTP request timeout in that script. Direct verification
uses `timeout=3600` in its attack `urlopen()` call. Browser and Ansible
verification use `timeout=1800.0` in their `http()` helpers. Values are in
seconds. Recreate the testbed before retrying; a host timeout does not
ensure that the attack inside the container has stopped.

## Repository Layout

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

Four long-lived containers and a one-shot key-generation container share
a Docker bridge network (`sshpoc`):

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

The client connects through the attacker on `:2222` and pins the SSH
server's host key in `known_hosts`. The forwarder relays SSH traffic
without terminating, decrypting, or modifying the SSH connection. The
scenario adapters inject chosen plaintext through the forwarded ports
and use the captured ciphertext lengths for recovery.


## HTTP Control API

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
`benchmark.py --early-exit` uses this to stop runs after an incorrect
byte is selected.

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


## Notes on Reusability

### Attack Engine and Adapters

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

`AttackConfig.overlay()` (in `attacker/attack/config.py`) applies JSON
overrides to the adapter's `default_config()`. Adding a scenario requires
an adapter, registration and construction in `attacker/mitm.py`, and
corresponding support in the benchmark harness.


### Modifying the Implementation

- `attacker/` and `client/` sources are `COPY`'d into the images at
  build time, not bind-mounted: rebuild the relevant service after
  edits (`docker compose build attacker && docker compose up -d attacker`).
- The alignment-data pool (`0x80..0x8F`), the per-scenario
  `commit_margin`, `flush_bytes=32768` (deflate's maximum search-buffer
  size), `guess_prefill_bytes=16384` (browser scenario only), and the
  adapter-specific ordering affect attack behavior. They are explained in Sections 4 and 5 of the paper and in the
  adapter docstrings. `outlier_threshold`, `constant_prefix_trim`, and
  `candidate_fork_on_stall` are implementation details with no
  counterpart in the paper; the latter is off in every configuration
  and therefore not exercised by the Table 3 runs.
- The 8-byte alignment sweep (`alignment_lengths=[0..7]`) assumes
  ChaCha20-Poly1305's padding granularity. AES-based modes pad to 16
  bytes and would require `[0..15]`, growing the sweep — and with it
  the guess count — linearly (cf. Section 8.1). The negotiated cipher
  is visible at `GET http://localhost:8000/status`.


## Generative AI Usage

The proof-of-concept implementations for each of the three attack
scenarios presented in Section 5 of the paper were implemented with
the help of Claude Code. We provided Claude Code with the description
of the generic attack, the assumed attacker model, descriptions for
the different scenarios, and an explicit requirement to avoid
shortcuts in its implementation. After implementation, we performed a
manual code review to ensure that the attacker model and the
implementation of each scenario are accurate and that no unexpected
shortcuts were taken. Dedicated integration tests verified end-to-end password recovery.
The manual review and these tests were used to validate the
implementations underlying the measurements in Table 3.
