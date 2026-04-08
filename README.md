# CRIME-on-SSH Proof of Concept

A self-contained Docker environment that demonstrates a CRIME-style
chosen-payload compression side-channel attack against the SSH binary
packet protocol. A passive in-the-middle observer recovers a secret
that the victim periodically sends on one logical channel by abusing
the fact that all SSH channels in one direction share a single zlib
compression context, and by triggering the victim to send chosen
payloads on a *second* logical channel and watching the encrypted
packet sizes on the wire.

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
6. [Two non-obvious knobs](#two-non-obvious-knobs)
7. [Results](#results)
8. [Repository layout](#repository-layout)
9. [HTTP control surface](#http-control-surface)
10. [Limitations and caveats](#limitations-and-caveats)
11. [References](#references)

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
  the encoder does a partial flush (Z_SYNC_FLUSH in AsyncSSH) but the
  LZ77 sliding window (32 KiB by default) and dynamic Huffman state
  carry over to the next packet.

So if the victim sends a secret on channel A and the attacker can
trigger the victim to send chosen bytes on channel B, the attacker's
bytes are compressed against an LZ77 dictionary that contains the
secret. That is exactly the CRIME setting, just at the SSH BPP layer
instead of the TLS record layer.

## Threat model

The attack assumes a **strong** adversary. All of the following must
hold:

1. **Forced compression.** The SSH client and server have negotiated
   a compressing algorithm (`zlib` or `zlib@openssh.com`). OpenSSH
   defaults to `none` for incoming connections and only enables
   `zlib@openssh.com` if the user passes `-C` or sets `Compression
   yes`, so this PoC is *not* a generic OpenSSH break.
2. **Two channels in use, one carrying the secret.** The victim has
   at least two logical channels open on the same SSH connection. At
   least one of them periodically transmits the secret (e.g. a
   service that pushes the password to a remote endpoint, an
   `rsync`/`scp` job that uploads a token, …).
3. **Attacker-controlled data on a second channel.** The attacker can
   coerce the victim to send chosen byte sequences on a different
   logical channel of the same connection. This is the "strong"
   bit. In this PoC the attacker triggers it via a small HTTP API on
   the client, which stands in for any of:
   - tailing an attacker-writable log file over an SSH session that
     happens to be doing something else,
   - a port-forwarded service that the attacker can write to,
   - an XSRF/SSRF gadget on a local HTTP daemon visible to the
     victim host,
   - a pre-configured `LocalForward`/`RemoteForward` whose other end
     is reachable by the attacker.
4. **Passive on-path observer.** The attacker sees ciphertext lengths
   on the wire. In the PoC the attacker is a TCP forwarder that the
   client connects to (so it sees every byte of every TCP segment
   trivially), but the host key of the *real* server is pinned, so
   any attempt at active in-the-middle would fail at the SSH layer.
5. **The attacker knows the public prefix of the secret.** Like
   CRIME's `Cookie: sid=`, here the attacker knows e.g. `PASSWORD=`
   and is recovering the value that follows.

The attack is read-only / observation-only at the SSH layer: it never
breaks SSH crypto and never modifies SSH traffic. The "I trigger the
victim to send chosen bytes" requirement is what makes it strong.

## Architecture

```
                     +------------+
                     |  poc-server|
                     |  AsyncSSH  |
                     |  :22       |
                     +------+-----+
                            ^
                            |  TCP forward
                            |
+----------+      +---------+--------+      +------------+
|poc-client| ---> |   poc-attacker   |      |  test/host |
|AsyncSSH  | TCP  |  scapy AsyncSniff|<---->| (curl/py)  |
|+aiohttp  | :2222|  TCP forwarder   |      |            |
|:8000     |      |  +aiohttp :9000  |      |            |
+----------+      +------------------+      +------------+
```

Three long-lived containers + a one-shot keygen container:

- **`poc-keygen`** — generates an Ed25519 host key and a client user
  key into a shared `keys/` volume on first start. Idempotent.
- **`poc-server`** — AsyncSSH server on port 22. Forces compression
  (`compression_algs=['zlib@openssh.com', 'zlib']`, no `none`
  fallback). Accepts public-key auth from one user. Spins up a
  trivial `process_factory` handler per channel that just consumes
  stdin and logs the byte count.
- **`poc-client`** — AsyncSSH client + aiohttp HTTP control plane on
  port 8000. Connects to `attacker:2222` (not directly to the
  server) but pins the *real* server's host key, so an active MitM
  is detected. Opens two long-lived session channels at startup:
  `secret-sink` and `attacker-sink`. The HTTP control plane lets
  the test harness/attacker trigger sends on either channel and
  swap the secret value at runtime via `/set_secret`.
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

The Docker bridge network (`sshpoc`) is the entire network the
attack lives on. Container hostnames (`server`, `attacker`,
`client`) are resolved by Docker's embedded DNS.

## Quick start

Requirements:

- Docker Desktop or any Docker engine that supports `docker compose`
- Python 3.x on the host (for the verification and test harness
  scripts; uses only the standard library)

```bash
# 1. Build images and bring everything up
cd SSH-Compression-PoC
docker compose up -d --build

# 2. Sanity-check the environment (SSH up, two channels, scapy
#    seeing wire sizes, attacker can trigger client sends):
python scripts/verify.py

# 3. Run the actual attack against five different secrets:
python scripts/test_attack.py
```

Expected output of step 3 (~9-12 minutes wall clock):

```
expected         recovered        time       status
---------------- ---------------- ---------- ------
hunter2          hunter2            92.7s    PASS
correcthorse     correcthorse      151.2s    PASS
pa55word         pa55word          104.5s    PASS
letmein9         letmein9          104.4s    PASS
tr0ub4dor        tr0ub4dor         115.9s    PASS

5/5 tests passed
```

To attack a single secret of your own:

```bash
# Set the secret on the client (this also reconnects SSH so the
# old secret is wiped from the LZ77 window)
curl -X POST http://127.0.0.1:8000/set_secret \
     -H 'Content-Type: application/json' \
     -d '{"value":"my-secret-here"}'

# Kick off the attack — recovered secret comes back in the response
curl -X POST http://127.0.0.1:9000/run_attack \
     -H 'Content-Type: application/json' \
     -d '{"known_prefix":"PASSWORD=",
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

The legitimate workflow on the client is:
```python
secret_proc.stdin.write(b"PASSWORD=" + value + b"\n")
```
which the attacker can model as a public prefix `PASSWORD=`,
an unknown value, and a known terminator `\n`. The attack recovers
`value` one byte at a time.

For each byte position, the attacker iterates over every candidate
character and an outer sweep of 16 noise lengths. For each
`(candidate, noise_length)` it does the following sequence:

```
1. flush_window()         -- send 33 KB of zeros on the attacker channel
2. refresh_secret()       -- trigger the client to send the secret on
                             the secret channel, putting it at the
                             most-recent end of the LZ77 dictionary
3. measure(prefix +       -- trigger the client to send the candidate
           candidate +       guess on the attacker channel and sum the
           noise)            c->s TCP payload bytes that scapy captured
```

The smallest sum across all `(noise_length × candidate)` measurements
identifies the recovered byte. We loop until the recovered byte is
the terminator `\n`.

### Why each step is there

**`flush_window`.** Without it, the *previous* attacker-channel BPP
message stays in the 32 KiB LZ77 sliding window and the new guess
back-references it as a length-18 prefix match. The candidate byte
gets buried inside the long backreference and the right vs wrong
candidates produce *identical* compressed output. Pushing 33 KB of
zeros on the attacker channel evicts the previous guess past the
window edge, so the new guess can only match against the secret
refresh that happened in step 2 — which is exactly what we want.

**`refresh_secret`.** Putting the secret at the most-recent end of
the dictionary makes the LZ77 backreference *distance* approximately
constant for both right and wrong candidates. Without this, the
distance-encoding cost (which depends on how many bytes ago the
match was) would dominate the right-vs-wrong cost difference. After a
fresh refresh both candidates match `PASSWORD=` at the same small
distance and the only signal that remains is the +1 *length* the
right candidate gets from matching the candidate byte.

**`measure`.** Sums the c→s TCP payload bytes that scapy captured
during this trigger. We use one half of the forwarder
(`dport == LISTEN_PORT`) so the same bytes traversing both legs of
the proxy aren't counted twice. The sum aggregates the constant
overhead from AsyncSSH's `MSG_IGNORE` injection and the variable
data packet, which is the only thing that depends on the candidate
byte.

### Where the signal lives

For a right candidate `c`:

- LZ77 finds `prefix + c` in the secret (length `len(prefix) + 1`).
- One backreference, no leftover literal.

For a wrong candidate `c'`:

- LZ77 finds `prefix` in the secret (length `len(prefix)`).
- One backreference + one literal byte for `c'`.

The compressed-bit difference is *usually* 8 bits (one literal saved)
but at length-code boundaries in the DEFLATE fixed-Huffman length
table it drops to **7 bits** because the wider length code costs one
extra bit. The wire-side packet length only changes when this
compressed-bit delta crosses a multiple of 8 bytes (the
chacha20-poly1305@openssh.com padding granularity) — see the next
section.

## Two non-obvious knobs

These two are what took most of the debugging:

### 1. `flush_bytes` ≥ 32 KiB

zlib's default LZ77 sliding window (`wbits=15`) is 32768 bytes. The
flush has to push enough input through the compressor between two
consecutive guesses that the *previous* guess BPP is past the window
edge. AsyncSSH splits writes larger than 32 KiB into multiple SSH
binary packets, so a flush of 33 000 bytes turns into a 32 768-byte
BPP plus a 232-byte BPP — together that's enough to make the previous
guess unreachable to LZ77.

If you reduce `flush_bytes` below ~32 800, the previous guess
remains in the window, the new guess matches it as a length-18
backreference, and **every candidate compresses to the same number
of bytes**. Margin = 0, attack picks the alphabetically first
candidate, and fails silently.

### 2. Noise has to be 9-bit DEFLATE literals (bytes 0xA0..0xAF)

The compressed-bit delta between right and wrong is **not always 8
bits**. At length-code transitions in the DEFLATE fixed-Huffman
length table — e.g. length 10 → 11 spans codes 264 → 265, where the
wider code costs one extra bit — the delta drops to **7 bits**. Seven
bits is less than one byte, and Z_SYNC_FLUSH's bit-to-byte alignment
slack happens to absorb it on most alignments.

To make the 7-bit delta cross a byte boundary at *some* noise length
we need to vary the bit-alignment of the rest of the compressed
payload across the noise sweep:

- DEFLATE fixed Huffman uses 8-bit literal codes for bytes 0..143
  and 9-bit literal codes for bytes 144..255.
- Adding an 8-bit literal grows the bit count by 8, which is 0 mod 8
  — the bit alignment doesn't change at all.
- Adding a 9-bit literal grows the bit count by 9, which is 1 mod 8
  — every noise byte shifts the alignment by one bit. Eight 9-bit
  literals cycle through all 8 possible alignments and *guarantee*
  at least one of them exposes the 7-bit compressed delta as a
  1-byte byte delta (which then crosses chacha's 8-byte padding
  boundary as an 8-byte wire delta).

The PoC uses bytes `0xA0..0xAF` (= 160..175):

- 9-bit literal class ✓
- distinct (so no 3-byte intra-noise LZ77 backreference can form) ✓
- not in any plausible dictionary content (zeros, ASCII, IGNORE
  filler `\x02 \x00*`, BPP wrappers) ✓

This is implemented by `_make_noise()` in
[`attacker/attack.py`](attacker/attack.py). Switching from 8-bit to
9-bit noise was the difference between `correcthorse` failing at
position 1 (margin 0) and recovering correctly with margin 16.

## Results

5 / 5 secrets recovered correctly end-to-end through the wire-side
scapy capture. No client-side leakage of the value, no
shortcut. Total wall clock for all five: ~9.5 minutes on Docker
Desktop on a Windows host.

```
expected         recovered        time       status
---------------- ---------------- ---------- ------
hunter2          hunter2            92.7s    PASS
correcthorse     correcthorse      151.2s    PASS
pa55word         pa55word          104.5s    PASS
letmein9         letmein9          104.4s    PASS
tr0ub4dor        tr0ub4dor         115.9s    PASS
```

Throughput: roughly 12-20 seconds per recovered byte with the
default settings. Per byte position the attack performs
`16 noise lengths × (alphabet + 1) candidates × 3 SSH messages`
(flush + secret refresh + guess) ≈ 1800 SSH messages.

## Repository layout

```
SSH-Compression-PoC/
├── README.md                  -- this file
├── docker-compose.yml         -- four services on the sshpoc bridge
├── keys/                      -- ed25519 keys generated by keygen
├── literature/                -- CRIME slides, RFCs 4250-4254, 1950, 1951
├── scripts/
│   ├── keygen.py              -- one-shot key generator
│   ├── verify.py              -- environment smoke test (no attack)
│   └── test_attack.py         -- end-to-end attack test against 5 secrets
├── server/
│   ├── Dockerfile
│   ├── requirements.txt       -- asyncssh, cryptography
│   └── server.py              -- AsyncSSH server with forced compression
├── client/
│   ├── Dockerfile
│   ├── requirements.txt       -- asyncssh, aiohttp, cryptography
│   └── client.py              -- AsyncSSH client + HTTP control plane
└── attacker/
    ├── Dockerfile
    ├── requirements.txt       -- scapy, aiohttp
    ├── mitm.py                -- TCP forwarder + scapy sniffer + control API
    └── attack.py              -- the actual chosen-payload attack
```

## HTTP control surface

### Client (`http://localhost:8000`)

| Method | Path                       | Description |
|--------|----------------------------|-------------|
| GET    | `/status`                  | Connection state, negotiated algs, channel state |
| POST   | `/send_secret`             | Triggers a send of the configured secret on the secret channel |
| POST   | `/send_attacker_payload`   | Body = bytes to send on the attacker channel |
| POST   | `/set_secret`              | JSON `{"value": "..."}` — swaps the secret and reconnects SSH |
| POST   | `/reset`                   | Tear down and re-open the SSH connection |
| GET    | `/compressed_log`          | **Debug-only.** Per-packet compressed sizes via a monkey-patched zlib compressor. The attacker container never queries this — it's used by ad-hoc probes only. |
| POST   | `/clear_compressed_log`    | Clear the debug log |

### Attacker (`http://localhost:9000`)

| Method | Path                | Description |
|--------|---------------------|-------------|
| GET    | `/status`           | Forwarder + sniffer state |
| GET    | `/packet_log`       | scapy-captured TCP segments since last clear |
| POST   | `/clear_log`        | Reset the packet log |
| POST   | `/trigger_secret`   | Convenience: forwards to client `/send_secret` |
| POST   | `/trigger_payload`  | Convenience: forwards to client `/send_attacker_payload` |
| POST   | `/run_attack`       | JSON parameters; runs the full attack and returns the recovered secret + per-position history |

`/run_attack` body fields (all optional):

```json
{
  "known_prefix":   "PASSWORD=",
  "alphabet":       "abcdefghijklmnopqrstuvwxyz0123456789",
  "max_length":     32,
  "noise_lengths":  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  "settle":         0.005,
  "flush_bytes":    33000
}
```

## Limitations and caveats

- **Strong adversary required.** See [Threat model](#threat-model).
  This is not "you can read SSH passwords off the wire". The
  attacker has to (a) have an on-path observation point and (b) be
  able to coerce the victim into sending chosen bytes on a second
  channel of the same SSH connection.
- **Compression must be enabled.** OpenSSH's `Compression` is `no`
  by default. Disabling compression entirely is the cleanest fix and
  has no security cost — the bandwidth savings are negligible
  on modern links anyway, which is essentially the recommendation
  CRIME made for TLS in 2012.
- **Throughput is bounded by the LZ77 flush.** Each guess sends a
  ~33 KiB dummy. On 1 Gbit/s wires this is sub-millisecond, but on
  HTTP-mediated control planes (like this PoC) the bottleneck is the
  HTTP roundtrip rather than the SSH IO.
- **Alphabet size and prefix knowledge matter.** The PoC assumes
  `[a-z0-9\n]` and a known `PASSWORD=` prefix. A binary secret with
  no known structure would need either a much larger alphabet or a
  different attack shape.
- **Tested only against AsyncSSH 2.18.** Other SSH implementations
  (OpenSSH, libssh, …) may differ in `MSG_IGNORE` injection
  behaviour, default zlib level, write-splitting threshold, and
  channel-data fragmentation, all of which affect the precise
  numbers though not the underlying signal.
- **chacha20-poly1305@openssh.com.** The wire-side analysis is
  specific to chacha20-poly1305's 8-byte padding granularity. AES-CTR
  + HMAC-ETM uses a 16-byte boundary which would require a wider
  noise sweep but doesn't fundamentally change the attack.

## Mitigations

- **Disable compression.** This kills the attack outright. SSH
  compression is opt-in in OpenSSH and the bandwidth savings on
  modern links are negligible, so this is the recommended fix.
- **Per-channel compression contexts.** Would isolate the secret
  channel from any attacker-controlled channel, even if compression
  is enabled. Requires a protocol extension to RFC 4253 §6.2.
- **Length-hiding padding.** AsyncSSH already inserts `MSG_IGNORE`
  packets before encrypted data, but the IGNORE messages have a
  constant compressed size, so they don't actually hide variation in
  the data packet. Real length-hiding would require *random*
  padding amounts (not just minimum-padding), which RFC 4253 permits
  but no implementation enables.

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
