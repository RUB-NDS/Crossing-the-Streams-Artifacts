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
  stdin and logs the byte count. **AsyncSSH is patched at image
  build time** to use RFC-mandated `Z_PARTIAL_FLUSH` instead of its
  stock `Z_SYNC_FLUSH` — see [AsyncSSH RFC 4253 patch](#asyncssh-rfc-4253-patch).
- **`poc-client`** — AsyncSSH client + aiohttp HTTP control plane on
  port 8000. Connects to `attacker:2222` (not directly to the
  server) but pins the *real* server's host key, so an active MitM
  is detected. Opens two long-lived session channels at startup:
  `secret-sink` and `attacker-sink`. The HTTP control plane lets
  the test harness/attacker trigger sends on either channel and
  swap the secret value at runtime via `/set_secret`. Same AsyncSSH
  `Z_PARTIAL_FLUSH` patch applied at build time.
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
1. flush_window()         -- send 33 KB of RANDOM bytes on the attacker
                             channel (evicts prior guesses from the LZ77
                             window AND keeps zlib's hash chains short)
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

**`flush_window`.** Two jobs in one:

- **LZ77 window eviction.** Without it, the *previous* attacker-channel
  BPP message stays in the 32 KiB LZ77 sliding window and the new
  guess back-references it as a length-18 prefix match. The candidate
  byte gets buried inside the long backreference and the right vs
  wrong candidates produce *identical* compressed output. Pushing
  ≥ 32 KiB of data on the attacker channel evicts the previous guess
  past the window edge, so the new guess can only match against the
  secret refresh that happened in step 2.
- **zlib hash-chain stabilisation.** The content of the flush
  matters. **An all-zeros flush saturates zlib's hash chain for
  `\x00\x00\x00`** with thousands of in-window positions; at level 6
  zlib's `max_chain_length` (128) gives up walking before reaching
  the optimal match and produces *sub-optimal, state-dependent*
  compression that can eat the per-candidate signal. Using
  **random bytes** keeps every hash chain short and lets zlib find
  the optimal match, so the compressed-byte progression matches the
  fresh-state predictions and the wire signal is preserved.

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
consecutive guesses that the *previous* guess BPP is past the window
edge. AsyncSSH splits writes larger than 32 KiB into multiple SSH
binary packets, so a flush of 33 000 bytes turns into a 32 768-byte
BPP plus a 232-byte BPP — together that's enough to make the previous
guess unreachable to LZ77.

**But size alone isn't enough.** An all-zeros flush saturates zlib's
hash chain for the 3-byte sequence `\x00\x00\x00`; under zlib's level
6 defaults the match search gives up after walking 128 chain positions
and picks a sub-optimal match whose exact choice depends on the prior
call sequence. That state-dependence eats the 1-byte per-candidate
signal in a significant fraction of byte positions.

Switching the flush to **cryptographically random bytes** (see
`secrets.token_bytes` in `_flush_window`) keeps every hash chain short
(each 3-byte sequence appears at most once or twice in a random
33 KiB block), so zlib's match search is both fast and optimal, and
the compressed-byte progression matches fresh-state predictions.

If you reduce `flush_bytes` below ~32 800 OR you switch the content
back to all-zeros, the attack mostly fails silently with margin = 0
at every position.

### 2. Noise has to be strictly-linear 8-bit DEFLATE literals (bytes 0x80..0x8F)

The compressed-bit delta between right and wrong is *usually* 8 bits
(one literal saved by the right candidate), but at length-code
transitions in the DEFLATE fixed-Huffman length table it drops to
**7 bits** because the wider length code costs one extra bit. Either
way, we need the compressed-byte count to **cross a chacha20-poly1305
8-byte padding boundary** at *some* noise length — otherwise the
right and wrong candidates both round to the same wire bin and the
margin is 0.

Sweeping 16 noise lengths (0..15) moves the compressed byte count
across a 16-byte range, which spans at least two chacha padding
bins. For this to reliably catch a boundary cross, the compressed
byte count must grow **strictly linearly** with the noise length:
no skipped values, no +2 jumps.

The cleanest way to get linear growth is noise bytes whose DEFLATE
fixed-Huffman literal code is *exactly 8 bits long*. DEFLATE assigns
8-bit codes to literals 0..143 and 9-bit codes to 144..255. 8-bit
literals add 8 bits = 1 byte each to the compressed stream, so each
extra noise byte grows the cmp byte count by exactly 1. 9-bit
literals would add 9 bits = 1 byte + 1 bit each, producing periodic
+2 jumps that *skip* one cmp value per cycle — and if the skipped
value happens to be the chacha boundary, the signal disappears.

The PoC picks bytes `0x80..0x8F` (= 128..143):

- 8-bit literal class ✓
- distinct (so no 3-byte intra-noise LZ77 backreference can form) ✓
- not in any plausible dictionary content (zeros, ASCII, `MSG_IGNORE`
  filler `\x02\x00*`, BPP wrappers) ✓

Implemented by `_make_noise()` in
[`attacker/attack.py`](attacker/attack.py).

### 3. AsyncSSH's `Z_SYNC_FLUSH` → `Z_PARTIAL_FLUSH`

Stock AsyncSSH 2.x calls `zlib.compressobj.flush(Z_SYNC_FLUSH)` at
the end of every SSH binary packet. RFC 4253 §6.2 instead specifies a
*partial flush* (zlib's `Z_PARTIAL_FLUSH`) — the same thing OpenSSH's
bundled zlib wrapper does. The difference:

- **Z_SYNC_FLUSH** appends a 5-byte empty *stored* block. Every
  compressed packet gains a constant 5-byte overhead and ends at a
  byte boundary with zero bit slack.
- **Z_PARTIAL_FLUSH** appends a ~10-bit empty *fixed* block. Packets
  are 3-4 bytes shorter on average, but the next packet's bit
  alignment is now variable, which changes the per-candidate
  signal's visibility at the wire layer.

For this PoC to say anything about *spec-conformant* SSH
implementations rather than just AsyncSSH's particular bug, we patch
AsyncSSH's compressor at Docker image build time to use
`Z_PARTIAL_FLUSH`. See the next section for how this is wired.

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
clock. The single failure was on `1fm4uu`, which tripped a rare
state-dependent edge case: at byte position 3 the 8-bit-literal
noise sweep's cmp progression happened to keep the right and wrong
candidates in the same chacha padding bin at every noise length and
the margin collapsed to 0. The attack then picked the alphabetically
first candidate (`a`) and slid into a self-reinforcing `aaa...` tail.

An earlier version of the PoC added a 9-bit-literal noise sweep as a
fallback to recover this class of edge case; it was removed for code
simplicity since ~98 % reliability is adequate for a research PoC.
See the commit history for the fallback implementation if you want
to bring it back.

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
├── docker-compose.yml         -- four services on the sshpoc bridge
├── keys/                      -- ed25519 keys generated by keygen
├── literature/                -- CRIME slides, RFCs 4250-4254, 1950, 1951
├── patches/
│   └── asyncssh-rfc4253-partial-flush.patch
│                              -- RFC 4253 §6.2 compliance patch for
│                                 asyncssh/compression.py, applied at
│                                 build time by client+server Dockerfiles
├── scripts/
│   ├── keygen.py              -- one-shot key generator
│   ├── verify.py              -- environment smoke test (no attack)
│   ├── test_attack.py         -- 5-secret regression suite
│   └── test_attack_random.py  -- 50-random-secret stress test
├── server/
│   ├── Dockerfile             -- applies the partial-flush patch
│   ├── requirements.txt       -- asyncssh, cryptography
│   └── server.py              -- AsyncSSH server with forced compression
├── client/
│   ├── Dockerfile             -- applies the partial-flush patch
│   ├── requirements.txt       -- asyncssh, aiohttp, cryptography
│   └── client.py              -- AsyncSSH client + HTTP control plane
└── attacker/
    ├── Dockerfile
    ├── requirements.txt       -- scapy, aiohttp
    ├── mitm.py                -- TCP forwarder + scapy sniffer + control API
    └── attack.py              -- the chosen-payload attack
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

`/run_attack` body fields (all optional, with shown defaults):

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
  This is not "you can read SSH passwords off the wire". The attacker
  has to (a) have an on-path observation point and (b) be able to
  coerce the victim into sending chosen bytes on a second channel of
  the same SSH connection.
- **Compression must be enabled.** OpenSSH's `Compression` is `no`
  by default. Disabling compression entirely is the cleanest fix and
  has no security cost — the bandwidth savings are negligible on
  modern links anyway, which is essentially the recommendation CRIME
  made for TLS in 2012.
- **~2 % edge-case failure rate on random secrets.** The 50-random
  stress test passes 49/50; the remaining state-dependent edge case
  (where the 8-bit-literal noise sweep's cmp values all land in the
  same chacha padding bin) can be handled by also sweeping 9-bit
  literal noise as a fallback, but that code path was removed for
  simplicity.
- **Throughput is bounded by HTTP roundtrips, not SSH.** Each guess
  sends a ~33 KiB dummy. On 1 Gbit/s wires this is sub-millisecond,
  but the HTTP-mediated control plane in this PoC adds a round-trip
  per message.
- **Alphabet size and prefix knowledge matter.** The PoC assumes
  `[a-z0-9\n]` and a known `PASSWORD=` prefix. A binary secret with
  no known structure would need either a much larger alphabet or a
  different attack shape.
- **Tested only against (patched) AsyncSSH 2.18.** Other SSH
  implementations (OpenSSH, libssh, …) may differ in `MSG_IGNORE`
  injection behaviour, default zlib level, write-splitting
  threshold, and channel-data fragmentation, all of which affect
  the precise numbers though not the underlying signal.
- **chacha20-poly1305@openssh.com.** The wire-side analysis is
  specific to chacha20-poly1305's 8-byte padding granularity.
  AES-CTR + HMAC-ETM uses a 16-byte boundary which would require a
  wider noise sweep but doesn't fundamentally change the attack.

## Mitigations

- **Disable compression.** This kills the attack outright. SSH
  compression is opt-in in OpenSSH and the bandwidth savings on
  modern links are negligible, so this is the recommended fix.
- **Per-channel compression contexts.** Would isolate the secret
  channel from any attacker-controlled channel, even if compression
  is enabled. Requires a protocol extension to RFC 4253 §6.2.
- **Length-hiding padding.** AsyncSSH already inserts `MSG_IGNORE`
  packets before encrypted data, but the IGNORE messages have a
  constant compressed size, so they don't actually hide variation
  in the data packet. Real length-hiding would require *random*
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
