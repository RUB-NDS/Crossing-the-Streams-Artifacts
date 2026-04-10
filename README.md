# CRIME-on-SSH Proof of Concept

A self-contained Docker environment that demonstrates a CRIME-style
chosen-payload compression side-channel attack against the SSH binary
packet protocol.  A passive on-path observer recovers the Redis
password that the victim's application sends through an SSH tunnel, by
abusing the fact that all SSH port-forwarded channels in one direction
share a single zlib compression context, and by injecting chosen
payloads through the same tunnel whose local endpoint is accessible on
the network.

> **Status: research / educational PoC.** This attack assumes a
> *strong* adversary (see [Threat model](#threat-model)) and is not
> immediately exploitable against typical SSH deployments. It is
> being published for responsible disclosure and to make the attack
> surface visible.

## Table of contents

1. [Background](#background)
2. [Threat model](#threat-model)
3. [Architecture](#architecture)
4. [Quick start](#quick-start)
5. [How the attack works](#how-the-attack-works)
6. [Three non-obvious knobs](#three-non-obvious-knobs)
7. [Results](#results)
8. [Repository layout](#repository-layout)
9. [HTTP control surface](#http-control-surface)
10. [Limitations and caveats](#limitations-and-caveats)
11. [Mitigations](#mitigations)
12. [References](#references)

## Background

[CRIME](literature/CRIME.pdf) (Rizzo & Duong, 2012) and its
descendants BREACH and HEIST exploit the fact that
**`len(encrypt(compress(attacker_input + secret)))` is leaked on the
wire**. When the attacker can choose part of the input that is
compressed together with a secret, varying their input and observing
the resulting ciphertext length is enough to recover the secret one
byte at a time. CRIME killed TLS-level compression; BREACH did the
same for HTTP-level compression.

The original CRIME presentation lists SSH as "not so sure if
exploitable" -- this PoC closes that gap.

The relevant SSH protocol facts (RFC 4253 section 6.2 and RFC 4254 section 5):

- SSH multiplexes any number of *logical channels* (sessions, port
  forwards, X11, ...) into one TCP connection.
- The negotiated compression algorithm (`zlib` or
  `zlib@openssh.com`) is applied at the **transport layer**, not per
  channel: there is exactly one zlib compression context per
  direction, shared across **all** channels.
- The compression context is stateful: after each SSH binary packet
  the encoder does a **partial flush** and the LZ77 sliding window
  (32 KiB by default) and dynamic Huffman state carry over to the
  next packet.

### The scenario

A developer tunnels Redis through a compressed SSH connection to a
bastion host -- the equivalent of:

```
ssh -C -L 0.0.0.0:6379:redis:6379 bastion
```

The tunnel is bound to `0.0.0.0` because the developer wants other
devices on the LAN -- containers, VMs, colleagues -- to reach the
Redis instance through the tunnel.  The developer's application
authenticates to Redis with `AUTH default <password>` through the
same tunnel.

An attacker on the same network segment connects to the tunnel on
port 6379 and sends chosen bytes.  Those bytes enter the SSH tunnel
as `direct-tcpip` channel data, sharing the c->s zlib compression
context with the victim's Redis AUTH traffic.  By observing
encrypted packet sizes on the wire, the attacker recovers the Redis
password byte by byte -- without ever breaking SSH crypto, without
shell access to the victim's machine, and without the victim's
credentials.

The client uses **redis-py** (`redis.asyncio`) for all Redis
interactions, so the `AUTH` command is sent in standard RESP wire
format:

```
*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$7\r\nhunter2\r\n
```

The attack exploits this framing in two phases: first it recovers
the password length digits, then the password itself.

## Threat model

The attack assumes a **strong** adversary. All of the following must
hold:

1. **Forced compression.** The SSH client and server have negotiated
   a compressing algorithm (`zlib` or `zlib@openssh.com`). OpenSSH
   defaults to `none` for incoming connections and only enables
   `zlib@openssh.com` if the user passes `-C` or sets `Compression
   yes`, so this PoC is *not* a generic OpenSSH break.
2. **Network-accessible port forward.** The victim has bound a
   tunnel to `0.0.0.0` (or a routable address) so other hosts on the
   LAN can reach it.  This is common when the developer wants
   containers, VMs, or colleagues to access the tunneled service.
   The attacker, on the same network segment, connects to this
   endpoint and sends chosen bytes which enter the SSH tunnel as
   `direct-tcpip` channel data.
3. **Attacker-injected and secret data share one zlib context.**
   The attacker's connections and the victim's application traffic
   both traverse the same SSH connection, so they share one c->s
   zlib compression context.
4. **Passive on-path observer.** The attacker sees ciphertext lengths
   on the wire. In the PoC the attacker is a TCP forwarder that the
   client connects to (so it sees every byte of every TCP segment
   trivially), but the host key of the *real* server is pinned, so
   any attempt at active in-the-middle would fail at the SSH layer.
   In the real world: shared WiFi, compromised router, ISP-level
   observation.
5. **The attacker knows the RESP prefix.** The attacker knows the
   client uses redis-py and the `default` ACL user, giving the
   constant RESP prefix `*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$`.
   This is analogous to CRIME's `Cookie: sid=`. Knowing the username
   a priori is optional as the attacker can exfiltrate it using the same
   technique as used for the password but with shorter prefix.
6. **Repeated secret transmission.** The victim's application must
   re-authenticate to Redis periodically (e.g., connection-pool
   churn, reconnects after timeouts). In the PoC the attacker
   triggers this via the client's HTTP control API; in practice the
   attacker waits for natural reconnection events or provokes them
   by crashing the existing Redis connection.

The attack is read-only / observation-only at the SSH layer: it never
breaks SSH crypto and never modifies SSH traffic.

## Architecture

```
                                                              +-----------+
                                                              | poc-redis |
                                                              | Redis 8   |
                                                              | :6379     |
                                                              +-----+-----+
                                                                    ^
                                                                    | fwd
                                                                    |
+----------+      +------------------+      +-------------+---------+
|poc-client| ---> |   poc-attacker   | ---> | poc-server  |
|OpenSSH   | TCP  |  TCP forwarder   | TCP  | OpenSSH     |
|+redis-py | :2222|  +scapy sniffer  | :22  | sshd        |
|+aiohttp  |      |  +aiohttp :9000  |      |             |
|:8000 ctrl|      +--+---------------+      +-------------+
+----------+         |
 :6379 <-------------+  attacker injects through exposed tunnel
```

Five long-lived containers + a one-shot keygen container:

- **`poc-keygen`** -- generates an Ed25519 host key and a client user
  key into a shared `keys/` volume on first start using `ssh-keygen`.
  Idempotent.
- **`poc-redis`** -- official Redis 8 (Alpine).  Started without a
  password; the client sets one via `CONFIG SET requirepass` after
  the SSH tunnel is up.
- **`poc-server`** -- OpenSSH server (`sshd`) on port 22 running on
  Debian bookworm-slim.  Forces compression (`Compression yes` in
  `sshd_config`).  Allows `direct-tcpip` channel requests for port
  forwarding (`AllowTcpForwarding yes`).  Accepts public-key auth
  only for a single user (`victim`).  OpenSSH's bundled zlib wrapper
  already uses RFC-mandated `Z_PARTIAL_FLUSH` between SSH binary
  packets.
- **`poc-client`** -- Python 3.14 container that manages an OpenSSH
  client subprocess (`ssh -N -C -v`) with one local port forward.
  Connects to `attacker:2222` (not directly to the server) but pins
  the *real* server's host key, so an active MitM is detected at the
  SSH layer.  Sets up the tunnel at startup:
  - `0.0.0.0:6379 -> redis:6379` (Redis tunnel, network-accessible)

  Uses **redis-py** (`redis.asyncio.Redis`) for all Redis
  interactions.  `AUTH` is sent in standard RESP wire format with
  `username='default'`.  An aiohttp HTTP control API on port 8000
  lets the test harness trigger a Redis AUTH cycle (`/send_secret`),
  change the password (`/set_secret`), and reconnect SSH (`/reset`).
- **`poc-attacker`** -- Three jobs in one container:
  1. A passive **TCP forwarder** between `:2222` and `server:22`.  It
     never terminates, decrypts, or modifies SSH.
  2. A **scapy `AsyncSniffer`** on `eth0` with BPF filter
     `tcp and (port 22 or port 2222)` that records the size of every
     TCP segment in both directions.
  3. An **aiohttp control API** on port 9000 with `/run_attack`
     (start the actual chosen-payload attack and return the
     recovered secret) plus `/packet_log`, `/clear_log`,
     `/trigger_secret`, `/trigger_payload`, `/status` for
     instrumentation.

  The attack injects payloads by opening TCP connections to
  `client:6379` (the exposed Redis tunnel).  This data enters
  the SSH tunnel as `direct-tcpip` channel data, sharing the c->s
  compression context with the victim's Redis AUTH traffic.

The Docker bridge network (`sshpoc`) is the entire network the
attack lives on.  Container hostnames (`server`, `attacker`,
`client`, `redis`) are resolved by Docker's embedded DNS.

## Quick start

Requirements:

- Docker Desktop or any Docker engine that supports `docker compose`
- Python 3.x on the host (for the verification and test harness
  scripts; uses only the standard library)

```bash
# 1. Build images and bring everything up
cd SSH-Compression-PoC
docker compose up -d --build

# 2. Sanity-check the environment (SSH up, port forward active,
#    attacker can observe wire sizes and inject through the tunnel):
python scripts/verify.py

# 3. Run the attack against the five canonical regression secrets:
python scripts/test_attack.py

# 4. (Optional) Stress-test against 50 random secrets of varying
#    length:
python scripts/test_attack_random.py
```

Expected output of step 3:

```
expected         recovered        time       status
---------------- ---------------- ---------- ------
hunter2          hunter2           259.5s    PASS
correcthorse     correcthorse      ...       PASS
pa55word         pa55word          ...       PASS
letmein9         letmein9          ...       PASS
tr0ub4dor        tr0ub4dor         ...       PASS

5/5 tests passed
```

To attack a single secret of your own:

```bash
# Set the Redis password on the client (this also reconfigures the
# real Redis server via CONFIG SET and reconnects SSH so the LZ77
# window is clean)
curl -X POST http://127.0.0.1:8000/set_secret \
     -H 'Content-Type: application/json' \
     -d '{"value":"my-secret-here"}'

# Kick off the attack.  Phase 1 recovers the RESP password length,
# phase 2 recovers the password itself.
# Phase 1 (recover password length):
curl -X POST http://127.0.0.1:9000/run_attack \
     -H 'Content-Type: application/json' \
     -d '{"known_prefix":"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$",
          "alphabet":"0123456789",
          "max_length":4}'

# Phase 2 (recover password, using the length from phase 1):
curl -X POST http://127.0.0.1:9000/run_attack \
     -H 'Content-Type: application/json' \
     -d '{"known_prefix":"*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$7\r\n",
          "alphabet":"abcdefghijklmnopqrstuvwxyz0123456789",
          "max_length":12}'
```

While an attack is running, watch progress in the attacker logs:

```bash
docker compose logs -f attacker
```

Each byte is reported with a
`pos N round=R best=X sum=S 2nd=Y sum=T margin=M` line.  The attack
repeats rounds until `margin >= 16`, ensuring every byte is confirmed
by a clear signal before being committed.

## How the attack works

The victim's application uses redis-py to authenticate to the real
Redis 8 server through the SSH tunnel.  redis-py sends the standard
RESP wire format:

```
*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$7\r\nhunter2\r\n
```

The constant prefix (before the password length) is 28 bytes:
`*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$`.  The attack proceeds
in two phases:

**Phase 1 -- recover the password length.** Known prefix =
`*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$`, alphabet = `0-9`,
terminator = `\r`.  Recovers e.g. `7`.

**Phase 2 -- recover the password.** Known prefix =
`*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$7\r\n` (includes the
recovered length and `\r\n` delimiter), alphabet = `a-z0-9`,
terminator = `\r`.  Recovers e.g. `hunter2`.

### Per-byte recovery with repeat-until-confident

For each byte position, the attack sweeps 8 noise lengths (0..7)
per **round** and accumulates candidate wire-byte sums across
rounds.  After each round the *margin* (difference between best and
second-best sum) is checked.  If `margin >= 16` the byte is
resolved; otherwise another round is run with fresh tunnel
connections whose SSH `CHANNEL_OPEN` bit-alignment jitter is
independent of previous rounds.  The real compression signal
(7-8 bits per correct candidate) grows linearly with rounds while
the jitter averages out.

Four progressive optimisations reduce work:

- **Candidate elimination.** After each round, candidates whose
  cumulative sum exceeds the best candidate's sum by more than
  `min_margin` are dropped.  Wrong candidates never compress
  smaller than the correct one, so their deficit is permanent;
  the minimum candidate count is clamped to 2 so the margin
  remains meaningful.
- **Adaptive noise sweep.** After the first full noise sweep,
  noise lengths that showed no differential signal (identical
  wire sizes for all candidates) are pruned.  Only productive
  noise lengths and their +/-1 neighbours are kept, reducing the
  per-round work from 8 to typically 3-5 noise lengths.
- **Noise hint carry-over.** The productive noise lengths from
  the previous byte position are shifted by +1 mod 8 (the prefix
  grew by one byte, so the padding-boundary crossing moves one
  noise length) and used as the initial noise set for the next
  position.  This often hits the productive region on round 1,
  avoiding an expensive full sweep.
- **Stall detection.** If the margin fails to grow for 2
  consecutive rounds and no candidates were eliminated, the active
  noise set is expanded by +/-1 (mod 8) to recover crossing lengths
  lost to channel jitter.

Within each round, for each `(candidate, noise_length)`:

```
1. flush_window()         -- open a throwaway tunnel connection and
                             send 33 KB of RANDOM bytes to evict
                             prior guesses from the LZ77 window
2. open_measure_tunnel()  -- open the measurement tunnel connection
                             BEFORE the secret so its CHANNEL_OPEN
                             lands on the far side of the secret in
                             the LZ77 window
3. refresh_secret()       -- trigger redis-py to connect and AUTH
                             through the tunnel, placing the secret
                             at the most-recent end of the LZ77
                             dictionary
4. measure(prefix +       -- clear the packet log, send the candidate
           candidate +       guess on the measurement tunnel, sum the
           noise)            c->s TCP payload bytes that scapy captured
```

The candidate with the smallest accumulated sum across all rounds
is the recovered byte.

### Why each step is there

**`flush_window`.** Two jobs in one:

- **LZ77 window eviction.** Pushing >= 32 KiB of random data through
  the tunnel evicts prior guesses past the 32 KiB window edge.
  Without this, the new guess back-references the previous guess and
  there is no signal.
- **zlib hash-chain stabilisation.** **Random bytes** keep every hash
  chain short so zlib finds the optimal match.  An all-zeros flush
  saturates the `\x00\x00\x00` hash chain and produces sub-optimal,
  state-dependent compression.

**`open_measure_tunnel` before `refresh_secret`.** The measurement
tunnel's `CHANNEL_OPEN` goes through the c->s compressor.  By opening
it *before* the Redis AUTH, the `CHANNEL_OPEN` lands in the LZ77
window on the far side of the secret, leaving **zero** channel-
management bytes between the AUTH data and the upcoming guess.

**`refresh_secret`.** The client opens a new Redis connection through
the tunnel using redis-py.  redis-py sends `AUTH default <password>`
in RESP format.  This creates a fresh `direct-tcpip` channel whose
data passes through the shared c->s compressor.

**`measure`.** Sends the guess through the measurement tunnel and sums
the c->s TCP payload bytes.  Both the Redis AUTH and the guess are
`direct-tcpip` channels on the same SSH connection, sharing one zlib
context.

### Where the signal lives

For a right candidate `c`:

- LZ77 finds `prefix + c` in the secret (match length `L + 1`).
- One backreference, no leftover literal.

For a wrong candidate `c'`:

- LZ77 finds `prefix` in the secret (match length `L`).
- One backreference + one literal byte for `c'`.

The compressed-bit difference is usually 8 bits (one literal saved),
but at DEFLATE length-code boundaries it drops to 7 bits.  Either
way, the right candidate is **always at least 7 bits cheaper** than
any wrong one.  The wire-side packet length only changes when this
delta crosses a chacha20-poly1305@openssh.com 8-byte padding
boundary -- which is why the noise sweep exists.

## Three non-obvious knobs

### 1. `flush_bytes` >= 32 KiB and random content

zlib's default LZ77 sliding window (`wbits=15`) is 32 768 bytes.
The flush has to push enough random input through the compressor to
evict the previous guess.  The data travels through the tunnel:
attacker -> `client:6379` -> SSH `direct-tcpip` channel -> server ->
`redis:6379`.  Redis receives binary garbage and closes the
connection; the attacker opens a fresh one for the next iteration.
The data has already passed through the SSH compressor.

**Random content is critical.** An all-zeros flush saturates zlib's
hash chain for `\x00\x00\x00`; at level 6 the match search gives up
after 128 chain entries and produces sub-optimal compression.
Cryptographically random bytes keep every chain short.

### 2. Noise bytes: 8-bit DEFLATE literals (0x80..0x8F)

Each noise byte must add *exactly* 8 compressed bits so the
compressed-byte count grows strictly linearly.  DEFLATE's fixed
Huffman table assigns 8-bit codes to literals 0..143, so bytes
`0x80..0x8F` (128-143) qualify.  They are distinct (no intra-noise
LZ77 matches) and absent from dictionary content (ASCII, zeros,
SSH framing).

### 3. Repeat-until-confident rounds

Opening a fresh tunnel connection per measurement introduces
bit-alignment jitter from the SSH `CHANNEL_OPEN` message (its
originator port varies).  A single 8-noise-length sweep may land
entirely in one chacha20 padding bin, giving margin = 0.  Repeating
rounds with independent jitter lets the signal accumulate while the
noise averages out.  The attack commits a byte only when
`margin >= 16` (configurable via `min_margin`).

## Results

### Single-secret benchmark (hunter2)

```
Phase 1: recovering password length...
  length = 7 (12.4s)
Phase 2: recovering password...
  password = 'hunter2' (246.0s)

Expected:  hunter2
Recovered: hunter2
Total:     259.5s
Status:    PASS
```

### Throughput

Roughly 20-40 seconds per recovered byte with the default settings.
Per byte position the attack performs
`N_noise x (alive_candidates + 1) x 3 SSH messages`
per round, where `N_noise` starts at 8 but is typically pruned to
3-5 after the first round, and candidates are progressively
eliminated.  Most byte positions resolve in 1-3 rounds at
`min_margin >= 16`.

## Repository layout

```
SSH-Compression-PoC/
+-- README.md                  -- this file
+-- docker-compose.yml         -- five services on the sshpoc bridge
+-- keys/                      -- ed25519 keys generated by keygen
+-- literature/                -- CRIME slides, BREACH slides, HEIST paper,
|                                 Kelsey 2002, RFCs 4250-4254, 1950, 1951
+-- scripts/
|   +-- keygen.sh              -- one-shot key generator (ssh-keygen)
|   +-- verify.py              -- environment smoke test (no attack)
|   +-- test_attack.py         -- 5-secret regression suite (two-phase RESP)
|   +-- test_attack_random.py  -- 50-random-secret stress test
+-- server/
|   +-- Dockerfile             -- debian:bookworm-slim + openssh-server
|   +-- sshd_config            -- Compression yes, PubkeyAuthentication yes,
|   |                             AllowTcpForwarding yes
|   +-- entrypoint.sh          -- copies host key, sets up authorized_keys,
|                                 runs sshd -D -e
+-- client/
|   +-- Dockerfile             -- python:3.14-slim + openssh-client
|   +-- requirements.txt       -- aiohttp, redis
|   +-- client.py              -- manages OpenSSH subprocess (ssh -N -C)
|                                 with one local port forward + redis-py
|                                 + HTTP control plane
+-- attacker/
    +-- Dockerfile
    +-- requirements.txt       -- scapy, aiohttp
    +-- mitm.py                -- TCP forwarder + scapy sniffer + control API
    +-- attack.py              -- the chosen-payload attack (injects through
                                  the Redis tunnel, observes Redis AUTH)
```

## HTTP control surface

### Client (`http://localhost:8000`)

| Method | Path                       | Description |
|--------|----------------------------|-------------|
| GET    | `/status`                  | Connection state, negotiated algs, port-forward state |
| POST   | `/send_secret`             | Opens a fresh redis-py connection through the tunnel; redis-py sends `AUTH default <password>` in RESP format |
| POST   | `/set_secret`              | JSON `{"value": "..."}` -- reconfigures the real Redis password via `CONFIG SET`, then reconnects SSH |
| POST   | `/reset`                   | Tear down and re-open the SSH connection |

### Attacker (`http://localhost:9000`)

| Method | Path                | Description |
|--------|---------------------|-------------|
| GET    | `/status`           | Forwarder + sniffer state |
| GET    | `/packet_log`       | scapy-captured TCP segments since last clear |
| POST   | `/clear_log`        | Reset the packet log |
| POST   | `/trigger_secret`   | Convenience: forwards to client `/send_secret` |
| POST   | `/trigger_payload`  | Sends payload through the Redis tunnel (TCP to client:6379) |
| POST   | `/run_attack`       | JSON parameters; runs the attack and returns the recovered value + per-position history |

`/run_attack` body fields (all optional, with shown defaults):

```json
{
  "known_prefix":   "*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$",
  "alphabet":       "abcdefghijklmnopqrstuvwxyz0123456789",
  "max_length":     32,
  "noise_lengths":  [0,1,2,3,4,5,6,7],
  "settle":         0.003,
  "flush_bytes":    33000,
  "min_margin":     16,
  "max_rounds":     64
}
```

## Limitations and caveats

- **Strong adversary required.** See [Threat model](#threat-model).
  This is not "you can read Redis passwords off the wire".  The
  attacker needs (a) an on-path observation point and (b) access to
  a network-bound port-forward endpoint on the same SSH connection
  that carries the secret.
- **Compression must be enabled.** OpenSSH's `Compression` is `no`
  by default.
- **Two-phase attack.** Because redis-py uses RESP wire format, the
  password length is encoded before the password.  The attack first
  recovers the length digits, then the password.
- **Alphabet and prefix knowledge matter.** The PoC assumes
  `[a-z0-9]` passwords and a known RESP prefix.  A binary secret
  with no known structure would need a much larger alphabet.
- **Throughput is bounded by HTTP round-trips, not SSH.** Each guess
  sends a ~33 KiB dummy flush through the tunnel, plus HTTP
  round-trips to the client's control API.
- **Tested against OpenSSH.** Both client and server use the
  standard OpenSSH implementation.  Other SSH implementations
  (libssh, PuTTY, ...) may differ in `MSG_IGNORE` injection,
  default zlib level, write-splitting, and channel-data
  fragmentation, all of which affect the precise numbers though not
  the underlying signal.  In particular, implementations that inject
  `MSG_IGNORE` packets before every `CHANNEL_DATA` (as AsyncSSH
  does) add measurement noise that requires a higher `min_margin`.
- **chacha20-poly1305@openssh.com.** The wire-side analysis is
  specific to chacha20-poly1305's 8-byte padding granularity.
  AES-CTR + HMAC-ETM uses a 16-byte boundary which would require a
  wider noise sweep but does not fundamentally change the attack.
- **Redis CONFIG SET.** The test harness changes the Redis password
  at runtime via `CONFIG SET requirepass`.

## Mitigations

- **Disable compression.** This kills the attack outright.  SSH
  compression is opt-in in OpenSSH and the bandwidth savings on
  modern links are negligible, so this is the recommended fix.
- **Per-channel compression contexts.** Would isolate each
  `direct-tcpip` channel, even if compression is enabled.
  Requires a protocol extension to RFC 4253 section 6.2.
- **Don't bind port forwards to 0.0.0.0.** Binding to `127.0.0.1`
  (the default for OpenSSH's `-L`) prevents remote hosts from
  reaching the tunnel endpoint.
- **Length-hiding padding.** Random padding amounts in SSH binary
  packets (RFC 4253 permits up to 255 bytes) would hide the
  compressed-size signal.  No implementation enables this by
  default.

## References

- Juliano Rizzo and Thai Duong.  *The CRIME attack.*
  Ekoparty / BlackHat 2012.  [literature/CRIME.pdf](literature/CRIME.pdf)
- Angelo Prado, Neal Harris, Yoel Gluck.  *SSL, gone in 30
  seconds: a BREACH beyond CRIME.*  BlackHat USA 2013.
  [literature/US-13-Prado-SSL-Gone-in-30-seconds-A-BREACH-beyond-CRIME-Slides.pdf](literature/US-13-Prado-SSL-Gone-in-30-seconds-A-BREACH-beyond-CRIME-Slides.pdf)
- Mathy Vanhoef and Tom Van Goethem.  *HEIST: HTTP encrypted
  information can be stolen through TCP-windows.*  BlackHat USA 2016.
  [literature/heist_blackhat2016.pdf](literature/heist_blackhat2016.pdf)
- John Kelsey.  *Compression and information leakage of plaintext.*
  FSE 2002.  [literature/23650264.pdf](literature/23650264.pdf)
- T. Ylonen and C. Lonvick.  *RFC 4253 -- The SSH Transport Layer
  Protocol* (compression in section 6.2).
  [literature/rfc4253.txt](literature/rfc4253.txt)
- T. Ylonen and C. Lonvick.  *RFC 4254 -- The SSH Connection
  Protocol* (channel multiplexing in section 5).
  [literature/rfc4254.txt](literature/rfc4254.txt)
- P. Deutsch.  *RFC 1951 -- DEFLATE Compressed Data Format
  Specification* (length and distance code tables in section 3.2.5).
  [literature/rfc1951.txt](literature/rfc1951.txt)
- P. Deutsch and J-L. Gailly.  *RFC 1950 -- ZLIB Compressed Data
  Format Specification.*
  [literature/rfc1950.txt](literature/rfc1950.txt)
