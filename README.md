# Crossing the Streams — PoC artifacts

A self-contained Docker environment that demonstrates a chosen-payload
compression side-channel attack against the SSH binary packet protocol.
A passive on-path observer recovers secrets that the victim sends
through a compressed SSH connection by abusing the fact that all SSH
channels in one direction share a single zlib compression context
(RFC 4253 §6.2).

These artifacts accompany the paper:

> **Crossing the Streams: SSH Plaintext Recovery via a Common
> Compression Context in Multiplexed Channels.**

Three attack variants are implemented, covering progressively weaker
attacker assumptions:

- **Direct** — the attacker opens raw TCP connections to a victim's
  exposed local port forward and injects data into the shared zlib
  context alongside the secret. Recovers a Redis `AUTH` password sent
  through the tunnel.
- **BEAST** — the victim visits an attacker-controlled website whose
  JavaScript makes `navigator.sendBeacon()` requests to `localhost`.
  The beacons land in the victim's own SSH port forward, entering the
  shared compression context. A headless Chromium is automated with
  Playwright.
- **Ansible** — the victim's system runs `ansible-playbook` jobs with
  `become: yes`, each of which spawns a fresh compressed SSH connection
  that inherits a `LocalForward` directive from `~/.ssh/config`. The
  attacker connects through that forward while the sudo password is
  in flight, injecting directly into the same zlib context.

> **Status: research / educational PoC.** The attack assumes a strong
> adversary (see [Threat model](#threat-model)) and is not
> immediately exploitable against typical SSH deployments. Artifacts
> are published to make the attack surface reproducible and to
> accompany the responsible-disclosure process.

## Table of contents

1. [Background](#background)
2. [Threat model](#threat-model)
3. [Architecture](#architecture)
4. [Quick start](#quick-start)
5. [How the attack works](#how-the-attack-works)
6. [Attack variants](#attack-variants)
7. [Load-bearing constants](#load-bearing-constants)
8. [Benchmark harness](#benchmark-harness)
9. [Results](#results)
10. [Repository layout](#repository-layout)
11. [HTTP control surface](#http-control-surface)
12. [Limitations and caveats](#limitations-and-caveats)
13. [Mitigations](#mitigations)
14. [References](#references)

## Background

[CRIME](literature/CRIME.pdf) (Rizzo & Duong, 2012) and its descendants
BREACH and HEIST exploit the fact that
**`len(encrypt(compress(attacker_input || secret)))` is leaked on the
wire**. When an attacker can choose part of the input that is compressed
together with a secret, varying their input and observing the resulting
ciphertext length is enough to recover the secret one byte at a time.
CRIME killed TLS-level compression; BREACH did the same for HTTP-level
compression. The original CRIME slide deck listed SSH as *"not so sure
if exploitable"* — this PoC closes that gap.

The relevant SSH protocol facts (RFC 4253 §6.2 and RFC 4254 §5):

- SSH multiplexes any number of *logical channels* (session, port
  forwards, X11, agent forwarding, ...) into one TCP connection.
- The negotiated compression algorithm (`zlib` or `zlib@openssh.com`)
  is applied at the **transport layer**, not per channel: there is
  exactly one zlib compression context per direction, shared across
  **all** channels multiplexed over the same connection.
- That compression context is stateful: after each SSH binary packet
  the encoder does a `Z_PARTIAL_FLUSH`, so the LZ77 sliding window
  (32 KiB by default) and dynamic Huffman state carry over into the
  next packet — and the next channel.

### The scenario

The "strong" reading of the attack assumes the attacker can choose
bytes that travel through the victim's compressed SSH connection
alongside a secret. In each PoC variant that assumption is grounded
in a realistic (if not ubiquitous) developer habit:

| Variant   | Victim's habit                                                           | Shared zlib context |
|-----------|--------------------------------------------------------------------------|---------------------|
| Direct    | `ssh -C -L 0.0.0.0:6379:redis:6379 bastion` — tunnel bound to all ifaces | Attacker dials the exposed forward port from the LAN |
| BEAST     | Any `LocalForward 127.0.0.1:6379:…` + the victim visits attacker JS      | `sendBeacon('http://localhost:6379', …)` from the victim's browser |
| Ansible   | Stale `LocalForward` in `~/.ssh/config` that Ansible inherits            | Attacker connects through the forward while `become:` passwords are in flight |

In each case the attacker and the victim both produce `direct-tcpip`
(or session) channels that feed the *same* zlib stream, and the
attacker observes ciphertext lengths on the wire by passive
sniffing.

## Threat model

The attack assumes a **strong adversary**. All of the following must
hold:

1. **Forced compression.** The SSH client and server have negotiated a
   compressing algorithm (`zlib` or `zlib@openssh.com`). OpenSSH
   defaults to `none` for incoming connections and only enables
   `zlib@openssh.com` if the user passes `-C` / sets `Compression
   yes`, so this PoC is *not* a generic OpenSSH break.
2. **A channel the attacker can inject on.** Variant-dependent: the
   victim has either (a) exposed a port-forward to a network the
   attacker can reach (direct), or (b) has a local-loopback forward
   that attacker-controlled JavaScript running in the victim's
   browser can reach via `sendBeacon()` (BEAST), or (c) has a
   long-lived `LocalForward` directive that a privileged automation
   (ansible/systemd timer/cron) inherits when it spawns a fresh ssh
   subprocess (ansible).
3. **Passive on-path observer.** The attacker sees ciphertext lengths
   on the wire. In the PoC the attacker is a TCP forwarder that the
   client connects to (so it sees every byte of every TCP segment
   trivially) — but the host key of the *real* server is pinned, so
   any active in-the-middle attempt is detected at the SSH layer. In
   the real world: shared Wi-Fi, compromised router, ISP-level
   observation.
4. **The attacker knows the framing prefix of the secret.** For Redis
   `AUTH` this is the RESP prefix
   `*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$`; for Ansible's sudo
   password it is the fixed 8-byte SSH `CHANNEL_DATA` header of the
   session channel. This is analogous to CRIME's `Cookie: sid=`.
5. **Repeated secret transmission.** The victim's application must
   re-send the secret periodically (e.g., reconnect after timeouts,
   connection-pool churn, or — for the ansible variant — the next
   scheduled playbook run).

The attack is read-only / observation-only at the SSH layer: it never
breaks SSH crypto and never modifies SSH traffic.

## Architecture

```
                                                               +-----------+
                                                               | poc-redis |
                                                               | Redis 8   |
                                                               +-----+-----+
                                                                     ^
                                                                     | fwd
+----------+      +------------------+      +-------------+----------+
|poc-client| ---> |   poc-attacker   | ---> | poc-server  |
|OpenSSH   | TCP  |  TCP forwarder   | TCP  | OpenSSH     |
|+redis-py | :2222|  +scapy sniffer  | :22  | sshd        |
|+ansible  |      |  +aiohttp :9000  |      |             |
|+Chromium |      +--+---------------+      +-------------+
|+aiohttp  |         |
|:8000 ctrl|         |
+----------+         |
 :6379 <-------------+  attacker injects through the exposed tunnel
 :15432 <------------+  or through the inherited Ansible LocalForward
```

Five long-lived containers plus a one-shot keygen:

- **`poc-keygen`** — generates an Ed25519 host key and a client user
  key into a shared `keys/` volume on first start. Idempotent.
- **`poc-redis`** — official Redis 8 (Alpine). Started without a
  password; the client sets one via `CONFIG SET requirepass` after
  the SSH tunnel is up.
- **`poc-server`** — OpenSSH server on Debian bookworm-slim. Forces
  compression (`Compression yes`), allows public-key auth for user
  `victim`, and permits `direct-tcpip` channels
  (`AllowTcpForwarding yes`).
- **`poc-client`** — Python 3.14 container that manages an OpenSSH
  subprocess (`ssh -N -C -v`) with two local port forwards (Redis
  tunnel on `0.0.0.0:6379`, Ansible `LocalForward` on
  `0.0.0.0:15432`), runs Redis-py, launches a headless Chromium via
  Playwright for the BEAST variant, and runs `ansible-playbook` jobs
  on demand for the Ansible variant. Exposes an aiohttp control API
  on port 8000.
- **`poc-attacker`** — three jobs in one process:
  1. A passive **TCP forwarder** between `:2222` and `server:22`. It
     never terminates, decrypts, or modifies SSH.
  2. A **scapy `AsyncSniffer`** on `eth0` with BPF filter
     `tcp and (port 22 or port 2222)` that records the size of every
     TCP segment in both directions.
  3. An **aiohttp control API** on port 9000 with a single
     `/run_attack` endpoint that dispatches to the unified attack
     engine via per-variant transport adapters.

The Docker bridge network (`sshpoc`) is the entire network that the
PoC lives on. Container hostnames (`server`, `attacker`, `client`,
`redis`) are resolved by Docker's embedded DNS.

## Quick start

Requirements:

- Docker Desktop or any Docker engine with `docker compose`
- Python 3 on the host (stdlib only; the verify / benchmark scripts
  use `urllib` / `json`)

```bash
# 1. Build images and bring everything up
docker compose up -d --build

# 2. Sanity-check the direct attack variant end-to-end
#    (verifies SSH up, compression negotiated, Redis tunnel active,
#     attacker observes packets, and finally recovers 'hunter2')
python scripts/verify_direct.py           # ~2 min

# 3. Verify the BEAST variant (browser + sendBeacon injection)
python scripts/verify_beast.py            # see "Results" for known limitation

# 4. Verify the Ansible variant (fresh SSH per ansible-playbook run)
python scripts/verify_ansible.py          # ~4 min

# 5. Run the scenario benchmark (all three variants, optimization presets)
python scripts/benchmark.py --stacks 4 --trials 100 --scenario all-opts
```

While an attack runs, watch per-byte progress in the attacker logs:

```bash
docker compose logs -f attacker
```

Each byte emits a
`pos N round=R best=X sum=S 2nd=Y margin=M alive=A align=L` line.

## How the attack works

The attack recovers a secret byte at a time by exploiting the
chosen-prefix / compressed-length oracle. The attacker's injection
and the victim's secret both enter the same zlib stream; LZ77
matches between them leak through the wire-byte count.

### Per-byte signal

For a byte position where the prefix is known and the next byte is
the target:

- **Right candidate `c`.** LZ77 matches `prefix + c` against the
  secret → match length *L+1*, one backreference token.
- **Wrong candidate `c'`.** LZ77 matches only `prefix` against the
  secret → match length *L*, plus one literal for `c'`.

The compressed-bit difference is typically **8 bits** (one literal
saved) under DEFLATE's fixed Huffman table, and sometimes 7 bits at
length-code boundaries. That 8-bit signal is invisible inside a
chacha20-poly1305 8-byte padding bin, so each position needs a
**sweep over alignment-data lengths** — appending 0..7 bytes of known
alignment data to the guess nudges the wire length across a padding
boundary, at which point the 8-bit signal becomes a 1-wire-byte
margin.

### Two phases

Against a redis-py `AUTH` frame the wire prefix is:

```
*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$<len>\r\n<password>\r\n
```

The PoC recovers the secret in two phases:

- **Phase 1** — constant prefix `*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$`,
  alphabet `0-9`, terminator `\r`. Recovers the length digit(s).
- **Phase 2** — prefix extended with the recovered length digits,
  alphabet `[a-z0-9]`, terminator `\r`. Recovers the password.

The Ansible variant uses the analogous two-phase framing against the
session-channel `CHANNEL_DATA` header `\x5e\x00\x00\x00\x00\x00\x00\x00`,
recovering the 9th byte (password length) first and then the
password itself.

### Repeat-until-confident

Opening a fresh channel per measurement introduces bit-alignment
jitter from each `CHANNEL_OPEN`'s random originator port. A single
alignment sweep can land entirely in one padding bin (margin = 0);
repeating rounds with independent jitter lets the signal accumulate
while the noise averages out. The engine commits a byte only when
the margin between the best and second-best candidate exceeds the
configured `min_margin`.

### Fork-on-stall (BEAST correctness fallback)

When a position exhausts `max_rounds` without reaching `min_margin`, the
engine speculatively runs the *next* position for each of the top-K
stalled candidates. Only the correct branch yields a clean commit at the
next position; wrong branches stall again or commit spurious bytes with
weak margins. A unique clean commit disambiguates the stalled position
and commits the next one at the same time. If two branches both commit
cleanly or none does, the engine recurses to 2-ply. On exhaustion, it
falls back to the best-margin candidate.

Direct and ansible variants rarely trigger this path because their
signals are clean; BEAST exhibits a persistent-bias edge case at
`hunter2` pos 4 that this fallback is specifically designed for.

### Constant-prefix trimming

As each byte is recovered, it is appended to the known prefix and
the front of the prefix is trimmed, keeping `len(prefix + candidate)`
constant across positions. This keeps the LZ77 match length in the
same DEFLATE length-code bin at every position, avoiding the 8→7-bit
signal drop at length-code boundaries (e.g. match length 34 → 35
crosses from code 272 to code 273).

## Attack variants

All three variants share the same engine. The difference is strictly
the **transport**: how the attacker's bytes and the victim's secret
both reach the shared zlib context.

### Direct — port-forward injection

The attacker opens a raw TCP connection to `client:6379` (the
exposed Redis tunnel). Each such connection becomes a fresh
`direct-tcpip` SSH channel that shares the c→s zlib context with the
victim's Redis `AUTH`.

Per oracle query:

```
1. flush          — 33 KiB random bytes via a throwaway connection,
                    to evict prior state from the LZ77 window
2. open_measure   — open the measurement connection BEFORE the secret,
                    so CHANNEL_OPEN lands on the far side of the secret
                    in the window
3. trigger_secret — fire a Redis AUTH via redis-py
4. send_guess     — write prefix + candidate + alignment on the
                    measurement connection
5. read           — sum observed c→s TCP payload bytes
```

### BEAST — browser injection

The victim's browser (headless Chromium in the PoC) visits an
attacker-controlled page served by the client itself on
`localhost:8000/exploit`. JavaScript on that page opens a WebSocket
back to the attacker and executes
`navigator.sendBeacon('http://localhost:6379', <body>)` on command.
Because `sendBeacon` fuses the TCP/HTTP `CHANNEL_OPEN` + data into
one request, there is no pre-opened measurement channel — the
adapter filters out small segments (≤ 100 bytes) to isolate the
`CHANNEL_DATA` packet from the `CHANNEL_OPEN` jitter.

The page is served from `localhost` specifically so that
`sendBeacon → localhost:6379` is a local-to-local request and
avoids Chrome's Private Network Access restrictions without any
browser flag.

### Ansible — fresh SSH per guess

The victim periodically runs `ansible-playbook` with `become: yes`.
Each invocation spawns a fresh ssh subprocess that inherits a
`LocalForward` directive from the victim's `~/.ssh/config` (a stale
forward the user set up months ago and forgot about). Ansible writes
the sudo password to that ssh's stdin, which OpenSSH wraps in a
single `SSH_MSG_CHANNEL_DATA` packet on the session channel.

Because every guess rides a brand-new SSH connection (and therefore
a fresh zlib context), the Ansible variant needs **no flush** — the
LZ77 window starts empty every time. The price is one SSH handshake
per iteration, so the variant is slow in absolute time but produces
the cleanest per-byte signal in the PoC (at exactly one alignment
length per position, the correct candidate measures exactly 8 bytes
less than every wrong candidate; at the other 7 alignment lengths
they're indistinguishable). A `fixed_single` alignment mode pinned
to the observed "winning" alignment length skips the 8× sweep and
recovers the password ~8× faster after the first position.

## Load-bearing constants

The following values underpin the attack and should not be casually
changed. They are documented in more detail in the package docstrings
(`attacker/attack/alignment.py`, `attacker/attack/adapters/*`) and
in `CLAUDE.md`.

### 1. `flush_bytes = 33000` (direct / BEAST only)

zlib's default LZ77 sliding window (`wbits=15`) is 32 768 bytes. The
flush must push enough random bytes through the encoder to evict the
previous iteration's state. The data travels through the tunnel,
reaches Redis as garbage, and closes the connection; the flush
content has already passed through the SSH compressor by then.

**Random content is critical.** An all-zeros flush saturates zlib's
hash chain for `\x00\x00\x00` and produces sub-optimal compression;
cryptographically random bytes keep every hash chain short. The
BEAST variant additionally restricts the flush to `0x80..0xFF` to
avoid LZ77 matches against the HTTP headers that `sendBeacon`
prepends.

The BEAST adapter regenerates the flush block on **every**
measurement, not only between rounds. A cached flush creates a
persistent LZ77 bias that averaging across rounds cannot remove.

### 2. Alignment-data pool = `0x80..0x8F`

Each alignment byte must add *exactly* 8 compressed bits so the
wire-byte count grows linearly. DEFLATE's fixed Huffman table assigns
8-bit codes to literals 0..143, so bytes `0x80..0x8F` (128..143) all
qualify. They are distinct (no intra-alignment LZ77 matches) and
absent from plausible dictionary content (ASCII text, zeros, SSH
framing). Do not substitute arbitrary bytes here.

### 3. Per-variant `min_margin`

The wire-byte gap between the best and second-best candidate that a
position must reach before being committed:

| Variant  | `min_margin` | Why |
|----------|--------------|-----|
| direct   | 16           | Low HTTP-header overhead; clean signal |
| BEAST    | 64           | HTTP headers + browser timing jitter |
| ansible  | 8            | Fresh zlib context per iteration; cleanest signal |

### 4. Adapter-specific ordering

- **direct**: flush → open_measure → trigger_secret → send_guess →
  measure → close. The measurement channel is opened *before* the
  secret so its `CHANNEL_OPEN` lands on the far side of the secret
  in the LZ77 window.
- **beast**: flush (via sendBeacon) → trigger_secret → send_guess
  (via sendBeacon) → measure. No pre-opened channel because
  sendBeacon fuses open + data.
- **ansible**: trigger_ansible → open_measure → send_guess →
  measure → close. No flush — fresh SSH per iteration.

### 5. `outlier_threshold` (BEAST only)

Chrome occasionally reuses TCP connections despite sendBeacon
semantics, which produces ~400-byte header-backreference anomalies.
The engine's baked-in outlier retry discards and re-runs any round
whose `max − min` measurement exceeds the threshold (32 bytes for
BEAST; 0 = disabled elsewhere).

## Benchmark harness

`scripts/benchmark.py` parallelises N independent docker-compose
projects (each a fully isolated stack: its own bridge network, its
own scapy sniffer) and collects per-attack and per-position guess
counts across scenarios and variants.

### Scenario presets

Each preset toggles a different combination of the five independent
optimization flags in `AttackConfig`. Transport-specific knobs
(`settle`, `flush_bytes`, `flush_pool`, `measurement_min_segment_size`,
`outlier_threshold`, `min_margin`) are *not* touched by presets; they
remain at the variant's tuned default, so scenarios stay apples-to-
apples across variants.

| Preset                  | alignment_mode | candidate_elim | prefix_trim | adaptive_align | stall_detect | hint_carryover |
|-------------------------|----------------|----------------|-------------|----------------|--------------|----------------|
| `baseline`              | fixed_single   | off            | on          | off            | off          | off            |
| `full-sweep`            | full_sweep     | off            | on          | off            | off          | off            |
| `candidate-elimination` | fixed_single   | on             | on          | off            | off          | off            |
| `adaptive-alignment`    | fixed_single   | off            | on          | on             | on           | on             |
| `all-opts`              | full_sweep     | on             | on          | on             | on           | on             |

Each non-`all-opts` preset isolates one axis of ablation against
`baseline`: `full-sweep` flips only the alignment mode,
`candidate-elimination` flips only candidate elimination, and
`adaptive-alignment` flips the adaptive-alignment cluster
(adaptive + stall-detect + hint carry-over). Presets that use
`fixed_single` require `--fixed-nl N` to pin the alignment length.

### Usage

```bash
# Three variants × 100 passwords, all optimizations on, 4 stacks in parallel
python scripts/benchmark.py --stacks 4 --trials 100 --scenario all-opts

# Baseline (fixed alignment length 1, no optimizations), direct variant only
python scripts/benchmark.py --stacks 2 --trials 50 \
    --variants direct --scenario baseline --fixed-nl 1

# Ablation: only candidate elimination on top of baseline
python scripts/benchmark.py --stacks 2 --trials 50 \
    --scenario candidate-elimination --fixed-nl 1

# Raw config override from a JSON file (overrides --scenario)
python scripts/benchmark.py --trials 20 --config my-config.json
```

Output:

- `benchmark_results.json` — full per-trial dump including each trial's
  `phase1_per_position` and `phase2_per_position` arrays (each entry:
  `{position, best, guesses, rounds, final_margin, successful_alignment,
  ranked_top5}`).
- `benchmark_summary.csv` — one row per `(variant, scenario)` with
  per-attack and per-position `min / max / avg / total` aggregates.

## Results

### Direct variant — `hunter2`

```
Phase 1: recovering password length...
  length = 7          ( ≈  5 s,  ≈ 160 guesses)
Phase 2: recovering password...
  password = 'hunter2' ( ≈100 s,  ≈2690 guesses)

Total:     ≈ 105 s
Guesses:   ≈ 2850
Status:    PASS
```

### Ansible variant — `hunter2`

```
Phase 1: recovering CHANNEL_DATA length byte...
  length byte = 0x08 (password length = 7)  (≈24 s)
Phase 2: recovering password...
  password = 'hunter2'                       (≈215 s)

Total:     ≈ 240 s
Status:    PASS
```

### BEAST variant — `hunter2`

```
Phase 1: recovering password length...
  length = 7          ( ≈ 15 s)
Phase 2: recovering password...
  password = 'hunter2' ( ≈ 20 min, 1 fork at pos 4)

Total:     ≈ 20 min
Status:    PASS (with fork-on-stall enabled — see below)
```

The BEAST per-round signal at pos 4 of `hunter2` exhibits a persistent,
non-random bias (`huntc` vs `hunte` within a few wire bytes) that
averaging across rounds cannot clear. The engine's **fork-on-stall**
correctness fallback disambiguates by speculatively running position 5
for the top-K stalled candidates and committing the branch that cleanly
resolves. Position 5 is committed from the winning branch's speculative
run, so the attack advances two positions at once. See
`docs/superpowers/specs/2026-04-22-fork-on-stall-design.md` for the
algorithm.

### Throughput comparison (indicative)

| Variant  | Ordering dominant cost | `hunter2` recovery | Per-byte cost |
|----------|------------------------|--------------------|---------------|
| direct   | TCP round-trip         | ≈ 2 min            | ≈ 15–30 s     |
| BEAST    | Browser + HTTP         | ≈ 20 min           | ≈ 60–180 s    |
| ansible  | SSH handshake          | ≈ 4 min            | ≈ 20–60 s     |

## Repository layout

```
Crossing-the-Streams-PoC/
├── README.md                                       -- this file
├── docker-compose.yml                              -- five services on the sshpoc bridge
├── docker-compose.bench.yml                        -- overlay for N parallel benchmark stacks
├── keys/                                           -- ed25519 host + client keys (generated)
├── literature/                                     -- CRIME, BREACH, HEIST slides + RFCs
├── docs/superpowers/
│   ├── specs/2026-04-22-unified-attack-design.md   -- design spec for the engine
│   └── plans/2026-04-22-unified-attack-engine.md   -- implementation plan (18 tasks)
├── scripts/
│   ├── keygen.sh                                   -- one-shot ssh-keygen wrapper
│   ├── verify_direct.py                            -- preconditions + hunter2 recovery (direct)
│   ├── verify_beast.py                             -- preconditions + hunter2 recovery (BEAST)
│   ├── verify_ansible.py                           -- preconditions + hunter2 recovery (ansible)
│   └── benchmark.py                                -- multi-stack scenario benchmark
├── server/                                         -- debian:bookworm-slim + openssh-server
│   ├── Dockerfile
│   ├── sshd_config                                 -- Compression yes, PubkeyAuth, TcpForwarding
│   └── entrypoint.sh
├── client/                                         -- python:3.14 + openssh-client + Chromium
│   ├── Dockerfile
│   ├── client.py                                   -- ssh subprocess + redis-py + ansible + browser
│   ├── ansible/                                    -- inventory + playbook for the ansible variant
│   └── requirements.txt
└── attacker/
    ├── Dockerfile
    ├── requirements.txt                            -- scapy, aiohttp
    ├── mitm.py                                     -- TCP forwarder + sniffer + /run_attack
    ├── exploit.html                                -- BEAST exploit page
    └── attack/                                     -- unified engine package
        ├── __init__.py
        ├── alignment.py                            -- _ALIGNMENT_POOL, make_alignment
        ├── config.py                               -- AttackConfig, AlignmentMode
        ├── engine.py                               -- run_attack, crack_byte_position
        ├── adapters/
        │   ├── base.py                             -- Adapter Protocol
        │   ├── direct.py                           -- raw-TCP injection
        │   ├── beast.py                            -- browser sendBeacon injection
        │   ├── ansible.py                          -- fresh-SSH-per-guess injection
        │   └── browser_bridge.py                   -- WebSocket bridge for BEAST
        └── tests/                                  -- plain-assertion sanity tests
            ├── test_alignment.py
            ├── test_config.py
            └── test_engine_helpers.py
```

## HTTP control surface

### Client (`http://localhost:8000`)

| Method | Path                     | Description |
|--------|--------------------------|-------------|
| GET    | `/status`                | SSH state, negotiated algorithms, port-forward state, browser state |
| GET    | `/exploit`               | Serves the BEAST exploit page (JS that dials the attacker via WebSocket) |
| POST   | `/send_secret`           | Opens a fresh redis-py connection through the tunnel — AUTH default \<password\> hits the wire |
| POST   | `/set_secret`            | `{"value": "..."}` — reconfigures the Redis password via `CONFIG SET`, then reconnects SSH |
| POST   | `/reset`                 | Tear down and re-open the SSH connection |
| POST   | `/send_secret_ansible`   | Kick off a fresh `ansible-playbook` run; returns when the sudo password has been written to ssh's stdin |
| POST   | `/set_sudo_secret`       | `{"value": "..."}` — rotates the sudo password via a root SSH login |

### Attacker (`http://localhost:9000`)

| Method | Path               | Description |
|--------|--------------------|-------------|
| GET    | `/status`          | Forwarder + sniffer state + browser connection state |
| GET    | `/packet_log`      | scapy-captured TCP segments since last clear |
| POST   | `/clear_log`       | Reset the packet log |
| POST   | `/trigger_secret`  | Convenience: proxies to client `/send_secret` |
| POST   | `/trigger_payload` | Writes a raw payload through the client's Redis tunnel |
| GET    | `/exploit`         | Serves the (secondary, unused) attacker-hosted exploit page |
| GET    | `/ws`              | WebSocket endpoint for the victim's browser (BEAST) |
| POST   | `/run_attack`      | **Unified attack endpoint** — dispatches on `variant` |

`/run_attack` request body (all `config` fields optional; omitted
fields fall back to the adapter's `default_config()`):

```json
{
  "variant": "direct | beast | ansible",
  "config": {
    "known_prefix":        "...",
    "alphabet":            "abcdefghijklmnopqrstuvwxyz0123456789",
    "max_length":          32,
    "terminator":          "\r",
    "min_margin":          16,
    "max_rounds":          64,
    "settle":              0.003,
    "alignment_mode":      "full_sweep",
    "alignment_lengths":   [0,1,2,3,4,5,6,7],
    "candidate_elimination":    true,
    "constant_prefix_trim":     true,
    "adaptive_alignment":       true,
    "stall_detection":          true,
    "alignment_hint_carryover": true,
    "outlier_threshold":   0,
    "flush_bytes":         33000,
    "flush_pool":          "secrets_random",
    "measurement_min_segment_size": 0,
    "label":               "all-opts"
  }
}
```

Response shape:

```json
{
  "ok": true,
  "variant": "direct",
  "config_label": "all-opts",
  "recovered": "hunter2",
  "elapsed_seconds": 101.3,
  "total_guesses": 2847,
  "per_position": [
    {"position": 0, "best": "h", "guesses": 432, "rounds": 4,
     "final_margin": 18, "successful_alignment": 1,
     "ranked_top5": [["h", 5120], ["t", 5138], ...]}
  ]
}
```

## Limitations and caveats

- **Strong adversary required.** See [Threat model](#threat-model).
  This is not "you can read Redis passwords off the wire."
- **Compression must be enabled.** OpenSSH's `Compression` defaults
  to `no`.
- **Alphabet and prefix knowledge matter.** The PoC assumes
  `[a-z0-9]` secrets and a known framing prefix. A binary secret
  with no known structure would need a much larger alphabet.
- **BEAST: persistent-bias edge case.** At some secret byte
  positions the per-round signal is genuinely insufficient to
  separate the correct candidate from a near-rival (observed at
  `hunter2` pos 4). Tracked as future work (see [Results](#results)).
- **Tested against OpenSSH only.** libssh, PuTTY, wolfSSH and others
  may differ in `MSG_IGNORE` injection, default zlib level, and
  channel-data fragmentation, which affect the constants but not
  the underlying signal.
- **chacha20-poly1305@openssh.com only.** The 8-byte padding
  granularity is specific to chacha20-poly1305. AES-CTR+HMAC-ETM
  uses a 16-byte boundary and would require a wider alignment sweep
  (alignment_lengths 0..15 rather than 0..7); the signal itself is
  unchanged.

## Mitigations

- **Disable compression.** Kills the attack outright. SSH
  compression is opt-in in OpenSSH and bandwidth savings on modern
  links are negligible — the recommended fix.
- **Per-channel compression contexts.** Would isolate each
  `direct-tcpip` / session channel from the others even with
  compression on. Requires a protocol extension to RFC 4253 §6.2
  and re-negotiation.
- **Don't bind port forwards to 0.0.0.0.** Binding to `127.0.0.1`
  (OpenSSH's `-L` default) prevents network-adjacent attackers from
  reaching the tunnel endpoint. Does not prevent BEAST (which
  injects from the victim's own browser).
- **Clean up unused `LocalForward` directives.** Stale forwards in
  `~/.ssh/config` are inherited silently by automation tools like
  Ansible. Audit them the way you audit `known_hosts`.
- **Length-hiding padding.** RFC 4253 permits up to 255 bytes of
  padding in SSH binary packets. No implementation enables random
  padding by default.

## References

- Juliano Rizzo, Thai Duong. *The CRIME attack.* Ekoparty /
  BlackHat 2012. [literature/CRIME.pdf](literature/CRIME.pdf)
- Angelo Prado, Neal Harris, Yoel Gluck. *SSL, gone in 30 seconds: a
  BREACH beyond CRIME.* BlackHat USA 2013.
  [literature/US-13-Prado-SSL-Gone-in-30-seconds-A-BREACH-beyond-CRIME-Slides.pdf](literature/US-13-Prado-SSL-Gone-in-30-seconds-A-BREACH-beyond-CRIME-Slides.pdf)
- Mathy Vanhoef, Tom Van Goethem. *HEIST: HTTP encrypted information
  can be stolen through TCP-windows.* BlackHat USA 2016.
  [literature/heist_blackhat2016.pdf](literature/heist_blackhat2016.pdf)
- John Kelsey. *Compression and information leakage of plaintext.*
  FSE 2002. [literature/23650264.pdf](literature/23650264.pdf)
- T. Ylonen, C. Lonvick. *RFC 4253 — The SSH Transport Layer
  Protocol* (compression in §6.2). [literature/rfc4253.txt](literature/rfc4253.txt)
- T. Ylonen, C. Lonvick. *RFC 4254 — The SSH Connection Protocol*
  (channel multiplexing in §5). [literature/rfc4254.txt](literature/rfc4254.txt)
- P. Deutsch. *RFC 1951 — DEFLATE Compressed Data Format
  Specification* (length / distance code tables in §3.2.5).
  [literature/rfc1951.txt](literature/rfc1951.txt)
- P. Deutsch, J-L. Gailly. *RFC 1950 — ZLIB Compressed Data Format
  Specification.* [literature/rfc1950.txt](literature/rfc1950.txt)
