# CRIME-on-SSH Proof of Concept

A self-contained Docker environment that demonstrates a CRIME-style
chosen-payload compression side-channel attack against the SSH binary
packet protocol.  A passive on-path observer recovers the Redis
password that the victim's application sends through an SSH tunnel, by
abusing the fact that all SSH port-forwarded channels in one direction
share a single zlib compression context, and by injecting chosen
payloads through a *second* port forward whose local endpoint is
accessible on the network.

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
7. [AsyncSSH RFC 4253 patch](#asyncssh-rfc-4253-patch)
8. [Results](#results)
9. [Repository layout](#repository-layout)
10. [HTTP control surface](#http-control-surface)
11. [Limitations and caveats](#limitations-and-caveats)
12. [Mitigations](#mitigations)
13. [References](#references)

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
exploitable" — this PoC closes that gap.

The relevant SSH protocol facts (RFC 4253 §6.2 and RFC 4254 §5):

- SSH multiplexes any number of *logical channels* (sessions, port
  forwards, X11, …) into one TCP connection.
- The negotiated compression algorithm (`zlib` or
  `zlib@openssh.com`) is applied at the **transport layer**, not per
  channel: there is exactly one zlib compression context per
  direction, shared across **all** channels.
- The compression context is stateful: after each SSH binary packet
  the encoder does a **partial flush** and the LZ77 sliding window
  (32 KiB by default) and dynamic Huffman state carry over to the
  next packet.

This PoC demonstrates a realistic scenario: a developer tunnels a
Redis server and an internal web application through one compressed
SSH connection.  An attacker on the same network connects to the
publicly-bound web tunnel and injects chosen bytes into the shared
c→s compression context, while observing encrypted packet sizes on
the wire.  The victim's Redis `AUTH <password>` command — sent
through a different tunnel on the *same* SSH connection — is
recovered byte by byte.

## Threat model

The attack assumes a **strong** adversary. All of the following must
hold:

1. **Forced compression.** The SSH client and server have negotiated
   a compressing algorithm (`zlib` or `zlib@openssh.com`). OpenSSH
   defaults to `none` for incoming connections and only enables
   `zlib@openssh.com` if the user passes `-C` or sets `Compression
   yes`, so this PoC is *not* a generic OpenSSH break.
2. **Two port forwards on one SSH connection.** The victim tunnels
   at least two services through the same SSH connection. One of
   them carries the secret (here: Redis `AUTH <password>`).
3. **One port forward is network-accessible.** The victim has bound
   at least one tunnel to `0.0.0.0` (or a routable address) so other
   hosts on the LAN can reach it. This is common when the developer
   wants containers, VMs, or colleagues to access the tunneled
   service. The attacker, on the same network segment, connects to
   this endpoint and sends chosen bytes which enter the SSH tunnel
   as `direct-tcpip` channel data.
4. **Passive on-path observer.** The attacker sees ciphertext lengths
   on the wire.  In the PoC the attacker is a TCP forwarder that the
   client connects to (so it sees every byte of every TCP segment
   trivially), but the host key of the *real* server is pinned, so
   any attempt at active in-the-middle would fail at the SSH layer.
   In the real world: shared WiFi, compromised router, ISP-level
   observation.
5. **The attacker knows the public prefix of the secret.** Like
   CRIME's `Cookie: sid=`, here the attacker knows the Redis inline
   command prefix `AUTH ` and is recovering the password that follows.
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
                     +-----------+      +----------+
                     | poc-redis |      |poc-webhost|
                     | Redis 7   |      | nginx    |
                     | :6379     |      | :80      |
                     +-----+-----+      +----+-----+
                           ^                  ^
                           |   internal net   |
                           |                  |
+----------+      +--------+---------+      +-+----------+
|poc-client| ---> |   poc-attacker   | ---> | poc-server  |
|AsyncSSH  | TCP  |  TCP forwarder   | TCP  | AsyncSSH    |
|+Redis app| :2222|  +scapy sniffer  | :22  | fwd-allowed |
|+aiohttp  |      |  +aiohttp :9000  |      |             |
|:8000 ctrl|      +------------------+      +-------------+
+----------+
 tunnels:
   127.0.0.1:6379  -> redis:6379    (secret: AUTH <password>)
   0.0.0.0:8080    -> webhost:80    (attacker-accessible)
```

Six long-lived containers + a one-shot keygen container:

- **`poc-keygen`** — generates an Ed25519 host key and a client user
  key into a shared `keys/` volume on first start. Idempotent.
- **`poc-redis`** — official Redis 7 (Alpine). Started without a
  password; the client sets one via `CONFIG SET requirepass` after
  the SSH tunnel is up.
- **`poc-webhost`** — official nginx (Alpine) serving a static cat
  picture gallery from `webhost/html/`.
- **`poc-server`** — AsyncSSH server on port 22. Forces compression
  (`compression_algs=['zlib@openssh.com', 'zlib']`, no `none`
  fallback). Allows `direct-tcpip` channel requests for port
  forwarding. Accepts public-key auth from one user. **AsyncSSH is
  patched at image build time** to use RFC-mandated
  `Z_PARTIAL_FLUSH` instead of its stock `Z_SYNC_FLUSH` — see
  [AsyncSSH RFC 4253 patch](#asyncssh-rfc-4253-patch).
- **`poc-client`** — AsyncSSH client + aiohttp HTTP control plane on
  port 8000. Connects to `attacker:2222` (not directly to the
  server) but pins the *real* server's host key, so an active MitM
  is detected. Sets up two local port forwards at startup:
  - `127.0.0.1:6379 -> redis:6379` (Redis tunnel, localhost only)
  - `0.0.0.0:8080 -> webhost:80` (web tunnel, network-accessible)

  The HTTP control plane lets the test harness trigger a Redis AUTH
  cycle (`/send_secret`), change the password (`/set_secret`), and
  reconnect SSH (`/reset`). Same AsyncSSH `Z_PARTIAL_FLUSH` patch.
- **`poc-attacker`** — Three jobs in one container:
  1. A passive **TCP forwarder** between `:2222` and `server:22`. It
     never terminates, decrypts, or modifies SSH.
  2. A **scapy `AsyncSniffer`** on `eth0` with BPF filter
     `tcp and (port 22 or port 2222)` that records the size of every
     TCP segment in both directions.
  3. An **aiohttp control API** on port 9000 with `/run_attack`
     (start the actual chosen-payload attack and return the
     recovered secret) plus `/packet_log`, `/clear_log`,
     `/trigger_secret`, `/trigger_payload`, `/status` for
     instrumentation.

  The attack injects payloads by opening a TCP connection to
  `client:8080` (the publicly-bound web tunnel).  This data enters
  the SSH tunnel as `direct-tcpip` channel data, sharing the c→s
  compression context with the Redis tunnel traffic.

The Docker bridge network (`sshpoc`) is the entire network the
attack lives on. Container hostnames (`server`, `attacker`,
`client`, `redis`, `webhost`) are resolved by Docker's embedded DNS.

## Quick start

Requirements:

- Docker Desktop or any Docker engine that supports `docker compose`
- Python 3.x on the host (for the verification and test harness
  scripts; uses only the standard library)

```bash
# 1. Build images and bring everything up
cd SSH-Compression-PoC
docker compose up -d --build

# 2. Sanity-check the environment (SSH up, port forwards active,
#    attacker can observe wire sizes and inject through the tunnel):
python scripts/verify.py

# 3. Run the attack against the five canonical regression secrets
#    (~10 minutes wall clock):
python scripts/test_attack.py

# 4. (Optional) Stress-test against 50 random secrets of varying
#    length (~100 minutes wall clock):
python scripts/test_attack_random.py
```

Expected output of step 3:

```
expected         recovered        time       status
---------------- ---------------- ---------- ------
hunter2          hunter2            98.3s    PASS
correcthorse     correcthorse      164.4s    PASS
pa55word         pa55word          110.9s    PASS
letmein9         letmein9          110.7s    PASS
tr0ub4dor        tr0ub4dor         123.8s    PASS

5/5 tests passed
```

To attack a single secret of your own:

```bash
# Set the Redis password on the client (this also reconfigures the
# real Redis server and reconnects SSH so the LZ77 window is clean)
curl -X POST http://127.0.0.1:8000/set_secret \
     -H 'Content-Type: application/json' \
     -d '{"value":"my-secret-here"}'

# Kick off the attack — recovered secret comes back in the response
curl -X POST http://127.0.0.1:9000/run_attack \
     -H 'Content-Type: application/json' \
     -d '{"known_prefix":"AUTH ",
          "alphabet":"abcdefghijklmnopqrstuvwxyz0123456789",
          "max_length":24}'
```

While an attack is running, watch progress in the attacker logs:

```bash
docker compose logs -f attacker
```

Each byte is reported with a `pos N best=X sum=S 2nd=Y sum=T margin=M`
line — `margin > 0` means the right candidate won by `M` wire bytes
across the noise sweep.

## How the attack works

The victim's application periodically authenticates to Redis through
the SSH tunnel:
```
AUTH hunter2\r\n
```
which the attacker can model as a known prefix `AUTH `, an unknown
password, and a known terminator `\r`. The attack recovers
the password one byte at a time.

For each byte position, the attacker iterates over every candidate
character and an outer sweep of 16 noise lengths. For each
`(candidate, noise_length)` it does the following sequence:

```
1. flush_window()         -- send 33 KB of RANDOM bytes through the
                             web tunnel (client:8080 -> SSH -> webhost)
                             to evict prior guesses from the LZ77
                             window AND keep zlib's hash chains short
2. refresh_secret()       -- trigger the client to open a new TCP
                             connection to 127.0.0.1:6379 (Redis tunnel)
                             and send AUTH <password>\r\n, putting the
                             secret at the most-recent end of the
                             LZ77 dictionary
3. measure(prefix +       -- send the candidate guess through the web
           candidate +       tunnel and sum the c->s TCP payload bytes
           noise)            that scapy captured
```

The smallest sum across all `(noise_length × candidate)` measurements
identifies the recovered byte. We loop until the recovered byte is
the terminator `\r`.

### Why each step is there

**`flush_window`.** Two jobs in one:

- **LZ77 window eviction.** Without it, the *previous* guess stays
  in the 32 KiB LZ77 sliding window and the new guess back-
  references it as a long match. Pushing ≥ 32 KiB of data through
  the web tunnel evicts the previous guess past the window edge.
- **zlib hash-chain stabilisation.** Using **random bytes** keeps
  every hash chain short and lets zlib find the optimal match. An
  all-zeros flush saturates zlib's hash chain for `\x00\x00\x00`
  and produces sub-optimal, state-dependent compression that eats
  the per-candidate signal.

**`refresh_secret`.** The client opens a new TCP connection to
`127.0.0.1:6379` (the Redis tunnel) and sends `AUTH <password>\r\n`.
This creates a fresh `direct-tcpip` channel whose data passes through
the shared c→s compressor, placing the secret at the most-recent end
of the LZ77 dictionary at an approximately constant distance from the
upcoming guess.

**`measure`.** Sends the guess through the web tunnel and sums the
c→s TCP payload bytes that scapy captured. Both the Redis AUTH and
the web tunnel guess are `direct-tcpip` channels on the same SSH
connection, sharing the same zlib compression context.

### Where the signal lives

For a right candidate `c`:

- LZ77 finds `prefix + c` in the secret (length `len(prefix) + 1`).
- One backreference, no leftover literal.

For a wrong candidate `c'`:

- LZ77 finds `prefix` in the secret (length `len(prefix)`).
- One backreference + one literal byte for `c'`.

The compressed-bit difference is *usually* 8 bits (one literal saved),
but at length-code boundaries in the DEFLATE fixed-Huffman length
table it drops to **7 bits** because the wider length code costs one
extra bit. Either way, the right candidate is **always at least 7
bits cheaper than any wrong candidate** (never more expensive — see
Correctness below). The wire-side packet length only changes when
this compressed-bit delta crosses a multiple of 8 bytes (the
chacha20-poly1305@openssh.com padding granularity) — see the next
section.

**Correctness.** Because the right candidate's compressed output is
always ≥ 7 bits cheaper, a *wrong* candidate can never have a
strictly-smaller wire size than the right candidate. Right and wrong
can be **tied** at the wire layer (when 7 or 8 bits sit inside the
Z_PARTIAL_FLUSH alignment slack), but right is **never** more
expensive. "Lowest sum wins" therefore never picks a wrong candidate
over a right one when a margin exists.

## Three non-obvious knobs

These are what took most of the debugging.

### 1. `flush_bytes` ≥ 32 KiB and random content

zlib's default LZ77 sliding window (`wbits=15`) is 32 768 bytes. The
flush has to push enough input through the compressor between two
consecutive guesses that the *previous* guess is past the window
edge. The flush data travels through the web tunnel: attacker →
`client:8080` → SSH `direct-tcpip` channel → server → `webhost:80`.
nginx receives a burst of binary garbage on what it thinks is an HTTP
connection and eventually closes it; the attacker simply reconnects
for the next round. The data has already passed through the SSH
compressor by then.

**But size alone isn't enough.** An all-zeros flush saturates zlib's
hash chain for the 3-byte sequence `\x00\x00\x00`; under zlib's level
6 defaults the match search gives up after walking 128 chain positions
and picks a sub-optimal match. Switching to **cryptographically
random bytes** keeps every hash chain short and the compression
optimal.

### 2. Noise has to be strictly-linear 8-bit DEFLATE literals (bytes 0x80..0x8F)

The compressed-bit delta between right and wrong is *usually* 8 bits,
but at length-code transitions it drops to **7 bits**. We need the
compressed-byte count to **cross a chacha20-poly1305 8-byte padding
boundary** at *some* noise length — otherwise right and wrong round
to the same wire bin and the margin is 0.

Sweeping 16 noise lengths (0..15) using bytes from `0x80..0x8F`
(8-bit fixed-Huffman literal class, distinct, not in any dictionary
content) moves the compressed byte count strictly linearly across a
16-byte range, spanning at least two padding bins.

### 3. AsyncSSH's `Z_SYNC_FLUSH` → `Z_PARTIAL_FLUSH`

Stock AsyncSSH 2.x calls `zlib.compressobj.flush(Z_SYNC_FLUSH)` at
the end of every SSH binary packet. RFC 4253 §6.2 instead specifies a
*partial flush* (zlib's `Z_PARTIAL_FLUSH`) — the same thing OpenSSH's
bundled zlib wrapper does. The patch makes AsyncSSH's compressor
match an RFC-compliant implementation.

## AsyncSSH RFC 4253 patch

The file [`patches/asyncssh-rfc4253-partial-flush.patch`](patches/asyncssh-rfc4253-partial-flush.patch)
is a single-hunk unified diff against
`asyncssh/compression.py` that:

- rewrites `_ZLibCompress.compress()` to call
  `self._comp.flush(zlib.Z_PARTIAL_FLUSH)` instead of `Z_SYNC_FLUSH`,
- updates the class and method docstrings to say so.

Both [`client/Dockerfile`](client/Dockerfile) and
[`server/Dockerfile`](server/Dockerfile) apply the patch after
`pip install` and verify the result with a post-apply `grep` that
fails the build if the patched file still contains
`flush(zlib.Z_SYNC_FLUSH)` or is missing `flush(zlib.Z_PARTIAL_FLUSH)`.

This makes the in-process SSH stack match what OpenSSH does on the
wire, so the attack's findings transfer to spec-conformant
implementations rather than being an artifact of an AsyncSSH bug.

## Results

### Five canonical regression secrets — 5/5

```
expected         recovered        time       status
---------------- ---------------- ---------- ------
hunter2          hunter2            98.3s    PASS
correcthorse     correcthorse      164.4s    PASS
pa55word         pa55word          110.9s    PASS
letmein9         letmein9          110.7s    PASS
tr0ub4dor        tr0ub4dor         123.8s    PASS
```

### Fifty random secrets (`test_attack_random.py`, seed 4253) — 49/50

A stress run against 50 random secrets drawn from `[a-z0-9]` with
lengths 3..14 recovered **49 / 50** correctly in ~104 minutes wall
clock. The single failure is on a rare state-dependent edge case
where the 8-bit-literal noise sweep keeps right and wrong candidates
in the same chacha padding bin at every noise length.

### Throughput

Roughly 12-20 seconds per recovered byte with the default settings.
Per byte position the attack performs `16 noise lengths × (alphabet
+ 1) candidates × 3 SSH messages` (flush + secret refresh + guess)
≈ 1800 SSH messages on the wire plus HTTP round-trips to the client
control plane. The HTTP RTT is the dominant bottleneck, not the SSH
throughput.

## Repository layout

```
SSH-Compression-PoC/
├── README.md                  -- this file
├── docker-compose.yml         -- six services on the sshpoc bridge
├── keys/                      -- ed25519 keys generated by keygen
├── literature/                -- CRIME slides, BREACH slides, HEIST paper,
│                                 Kelsey 2002, RFCs 4250-4254, 1950, 1951
├── patches/
│   └── asyncssh-rfc4253-partial-flush.patch
│                              -- RFC 4253 §6.2 compliance patch for
│                                 asyncssh/compression.py
├── webhost/
│   └── html/                  -- static cat gallery served by nginx
│       ├── index.html
│       └── images/cat{1..4}.svg
├── scripts/
│   ├── keygen.py              -- one-shot key generator
│   ├── verify.py              -- environment smoke test (no attack)
│   ├── test_attack.py         -- 5-secret regression suite
│   └── test_attack_random.py  -- 50-random-secret stress test
├── server/
│   ├── Dockerfile             -- applies the partial-flush patch
│   ├── requirements.txt       -- asyncssh, cryptography
│   └── server.py              -- AsyncSSH server with forced compression
│                                 and direct-tcpip forwarding enabled
├── client/
│   ├── Dockerfile             -- applies the partial-flush patch
│   ├── requirements.txt       -- asyncssh, aiohttp, cryptography
│   └── client.py              -- AsyncSSH client with two local port
│                                 forwards + HTTP control plane
└── attacker/
    ├── Dockerfile
    ├── requirements.txt       -- scapy, aiohttp
    ├── mitm.py                -- TCP forwarder + scapy sniffer + control API
    └── attack.py              -- the chosen-payload attack (injects through
                                  the web tunnel, observes Redis AUTH)
```

## HTTP control surface

### Client (`http://localhost:8000`)

| Method | Path                       | Description |
|--------|----------------------------|-------------|
| GET    | `/status`                  | Connection state, negotiated algs, port-forward state |
| POST   | `/send_secret`             | Triggers one Redis AUTH cycle through the tunnel |
| POST   | `/set_secret`              | JSON `{"value": "..."}` — reconfigures the real Redis password via CONFIG SET, then reconnects SSH |
| POST   | `/reset`                   | Tear down and re-open the SSH connection |
| GET    | `/compressed_log`          | **Debug-only.** Per-packet compressed sizes via a monkey-patched zlib compressor. The attacker container never queries this. |
| POST   | `/clear_compressed_log`    | Clear the debug log |

### Attacker (`http://localhost:9000`)

| Method | Path                | Description |
|--------|---------------------|-------------|
| GET    | `/status`           | Forwarder + sniffer state |
| GET    | `/packet_log`       | scapy-captured TCP segments since last clear |
| POST   | `/clear_log`        | Reset the packet log |
| POST   | `/trigger_secret`   | Convenience: forwards to client `/send_secret` |
| POST   | `/trigger_payload`  | Sends payload through the web tunnel (TCP to client:8080) |
| POST   | `/run_attack`       | JSON parameters; runs the full attack and returns the recovered secret + per-position history |

`/run_attack` body fields (all optional, with shown defaults):

```json
{
  "known_prefix":   "AUTH ",
  "alphabet":       "abcdefghijklmnopqrstuvwxyz0123456789",
  "max_length":     32,
  "noise_lengths":  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  "settle":         0.005,
  "flush_bytes":    33000
}
```

## Limitations and caveats

- **Strong adversary required.** See [Threat model](#threat-model).
  This is not "you can read Redis passwords off the wire". The
  attacker has to (a) have an on-path observation point and (b) be
  able to send data through a port-forward endpoint on the same SSH
  connection that carries the secret.
- **Compression must be enabled.** OpenSSH's `Compression` is `no`
  by default. Disabling compression entirely is the cleanest fix.
- **~2 % edge-case failure rate on random secrets.** The 50-random
  stress test passes 49/50; the remaining state-dependent edge case
  can be handled by a 9-bit-literal noise sweep fallback.
- **Throughput is bounded by HTTP roundtrips, not SSH.** Each guess
  sends a ~33 KiB dummy flush through the web tunnel. On 1 Gbit/s
  wires this is sub-millisecond, but the HTTP-mediated control plane
  adds a round-trip per message.
- **Alphabet size and prefix knowledge matter.** The PoC assumes
  `[a-z0-9\r]` and a known `AUTH ` prefix. A binary secret with
  no known structure would need a much larger alphabet.
- **Tested only against (patched) AsyncSSH 2.18.** Other SSH
  implementations (OpenSSH, libssh, …) may differ in `MSG_IGNORE`
  injection behaviour, default zlib level, write-splitting
  threshold, and channel-data fragmentation.
- **chacha20-poly1305@openssh.com.** The wire-side analysis is
  specific to chacha20-poly1305's 8-byte padding granularity.
  AES-CTR + HMAC-ETM uses a 16-byte boundary which would require a
  wider noise sweep but doesn't fundamentally change the attack.
- **Redis CONFIG SET.** The test harness changes the Redis password
  at runtime via `CONFIG SET requirepass`. The first test secret
  (`hunter2`) always matches the initial password; subsequent
  secrets are reconfigured live.

## Mitigations

- **Disable compression.** This kills the attack outright. SSH
  compression is opt-in in OpenSSH and the bandwidth savings on
  modern links are negligible, so this is the recommended fix.
- **Per-channel compression contexts.** Would isolate the Redis
  tunnel from the web tunnel, even if compression is enabled.
  Requires a protocol extension to RFC 4253 §6.2.
- **Don't bind port forwards to 0.0.0.0.** Binding to `127.0.0.1`
  (the default for OpenSSH's `-L`) prevents remote hosts from
  reaching the tunnel endpoint.  The PoC's scenario requires the
  web tunnel to be network-accessible.
- **Length-hiding padding.** Random padding amounts in SSH binary
  packets (RFC 4253 permits up to 255 bytes) would hide the
  compressed-size signal. No implementation enables this.

## References

- Juliano Rizzo and Thai Duong. *The CRIME attack.*
  Ekoparty / BlackHat 2012. [literature/CRIME.pdf](literature/CRIME.pdf)
- Angelo Prado, Neal Harris, Yoel Gluck. *SSL, gone in 30
  seconds: a BREACH beyond CRIME.* BlackHat USA 2013.
  [literature/US-13-Prado-SSL-Gone-in-30-seconds-A-BREACH-beyond-CRIME-Slides.pdf](literature/US-13-Prado-SSL-Gone-in-30-seconds-A-BREACH-beyond-CRIME-Slides.pdf)
- Mathy Vanhoef and Tom Van Goethem. *HEIST: HTTP encrypted
  information can be stolen through TCP-windows.* BlackHat USA 2016.
  [literature/heist_blackhat2016.pdf](literature/heist_blackhat2016.pdf)
- John Kelsey. *Compression and information leakage of plaintext.*
  FSE 2002. [literature/23650264.pdf](literature/23650264.pdf)
- T. Ylonen and C. Lonvick. *RFC 4253 — The SSH Transport Layer
  Protocol* (compression in §6.2).
  [literature/rfc4253.txt](literature/rfc4253.txt)
- T. Ylonen and C. Lonvick. *RFC 4254 — The SSH Connection
  Protocol* (channel multiplexing in §5).
  [literature/rfc4254.txt](literature/rfc4254.txt)
- P. Deutsch. *RFC 1951 — DEFLATE Compressed Data Format
  Specification* (length and distance code tables in §3.2.5).
  [literature/rfc1951.txt](literature/rfc1951.txt)
- P. Deutsch and J-L. Gailly. *RFC 1950 — ZLIB Compressed Data
  Format Specification.*
  [literature/rfc1950.txt](literature/rfc1950.txt)
