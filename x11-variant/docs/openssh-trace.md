# Why repeated X11-forward probes get clipped: an OpenSSH source trace

This document traces the exact OpenSSH code path that defeats the
`x11-fwd` PoC's CRIME-style design. Source references are against
[openssh/openssh-portable](https://github.com/openssh/openssh-portable)
master at the time of this writing.

## Problem statement

Empirically, the *first* attacker connection to `127.0.0.1:60NN`
flows the full payload server→client (≈10 KiB visible in
`/sys/class/net/eth0/statistics/tx_bytes`). Every *subsequent*
connection in the same SSH session forwards only ≈400 bytes, regardless
of payload size or content. With only a few hundred bytes of
attacker-controlled data per probe, and most of those bytes being
fixed channel-setup/teardown framing, the per-probe compression delta
is buried below the measurement floor.

## What the SSH client is doing on each probe

```
sshd's localhost:60NN listener accept()s cotenant TCP connection
            │
            ▼
sshd creates a per-connection channel of type "x11-connection"
   channels.c::channel_post_x11_listener  (lines 1900-1948)
            │
            ▼
sshd → client:  SSH_MSG_CHANNEL_OPEN(type="x11", new channel ID)
            │
            ▼
client receives, calls clientloop.c::client_request_x11
   clientloop.c::client_input_channel_open  (line 1917)
   clientloop.c::client_request_x11         (line 1796)
            │
            ▼
client opens TCP to local X server (Xvfb), creates a Channel of type
SSH_CHANNEL_X11_OPEN (clientloop.c:1827)
            │
            ▼
client → sshd:  SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            │
            ▼
sshd starts forwarding bytes from cotenant's local TCP socket
into the channel as SSH_MSG_CHANNEL_DATA
            │
            ▼
client receives the first chunk of CHANNEL_DATA on the channel.
Channel is in state SSH_CHANNEL_X11_OPEN, so its pre-handler is
channels.c::channel_pre_x11_open (registered at line 2616).
            │
            ▼
channels.c::channel_pre_x11_open       (lines 1465-1483)
   └── int ret = x11_open_helper(ssh, c->output);
                 │
                 ▼
   channels.c::x11_open_helper          (lines 1373-1437)
      ─ checks if first 12 bytes are buffered (line 1388)
      ─ reads byte-order indicator at offset 0 (lines 1393-1399)
      ─ MUST be 0x42 ('B') or 0x6c ('l').
      ─ Anything else → debug2("Initial X11 packet contains bad
                                byte order byte: 0x%x") and return -1
                        (lines 1399-1403)
      ─ otherwise reads proto_len, data_len; checks full packet
        is buffered (lines 1406-1408)
      ─ compares 18 bytes at offset 12 to "MIT-MAGIC-COOKIE-1"
        (s->x11_saved_proto)
      ─ compares 16 bytes after that to s->x11_fake_data
        (the fake cookie sent in x11-req) using timingsafe_bcmp
        (lines 1417-1422)
      ─ on any mismatch → return -1
            │
            ▼
   ret == -1  →  channel_pre_x11_open does:
      logit("X11 connection rejected because of wrong authentication.")
      channels.c::channel_force_close(ssh, c, 0)   (line 1481)
            │
            ▼
   channels.c::channel_force_close      (lines 1439-1463)
      ─ chan_read_failed(ssh, c)        (CHAN_INPUT_OPEN branch)
      ─ sshbuf_reset(c->output)         (line 1451) — DROPS unsent data
      ─ chan_write_failed(ssh, c)
      ─ etc.
            │
            ▼
client → sshd:  SSH_MSG_CHANNEL_CLOSE
            │
            ▼
sshd cleans up its end of this channel. Listener stays alive.
Cotenant's TCP socket gets closed.
```

## Why the *first* probe leaks the full payload

Between sshd opening the channel and the client's x11_open_helper
deciding to reject, there's a round-trip and several syscalls. During
that window, sshd's `client_post_open` reads as much as it can from
the cotenant's local TCP socket and queues it in the channel's
output buffer (`c->output`). It then sends those bytes as one or more
CHANNEL_DATA messages as soon as the channel is open.

For a 10 KiB probe, the cotenant's `sendall` plus TCP send-buffer can
hand sshd the entire payload before the rejection round-trip
completes. sshd ships all of it in CHANNEL_DATA messages →
`tx_bytes` reflects the full ≈10 KiB.

## Why every *subsequent* probe is clipped

Each new probe is a fresh TCP connection from the cotenant, a fresh
listener-accept on sshd, a fresh x11-connection channel. The channel
goes through the same SSH_CHANNEL_OPENING → SSH_CHANNEL_X11_OPEN →
rejection cycle, but with materially different *timing*:

- TCP path is warm (no first-segment slow-start, kernel buffers
  pre-allocated).
- sshd's per-channel state allocation paths are cache-warm.
- The SSH client's main event loop is already iterating fast.

Empirically the rejection round-trip on the second-and-later probes
completes before sshd has the chance to ship more than one or two
CHANNEL_DATA messages. The channel-close cascade fires, and:

- channel_force_close at channels.c:1451 calls
  `sshbuf_reset(c->output)` on the **client side**, dropping any
  unsent data still buffered there.
- On the **server side**, sshd receives CHANNEL_CLOSE for the
  half-open x11-connection channel and stops reading from the
  cotenant's local socket. Any kernel-buffered cotenant bytes
  beyond what was already read get discarded once the local socket
  is closed.

The result is the observed ~400 bytes of egress per probe — that's
roughly: CHANNEL_OPEN + CHANNEL_OPEN_CONFIRMATION (rx, doesn't
count) + a single small CHANNEL_DATA + CHANNEL_CLOSE, all encrypted
with ChaCha20-Poly1305 framing.

## The architectural takeaway

`x11_open_helper`'s rejection isn't "soft" — it's destructive:

1. Returns -1 the moment the first 12+ bytes look wrong.
2. Triggers `channel_force_close`, which **resets the channel's output
   buffer** (channels.c:1451). Any pending cotenant data already queued
   for transmission server→client is dropped client-side.
3. Drives the channel state to closed, which propagates back to sshd
   via CHANNEL_CLOSE. sshd's local TCP socket is closed, dropping
   any further cotenant bytes that hadn't been read yet.

Combined with the second-and-later-probe timing — where the rejection
arrives at sshd before more than a couple of CHANNEL_DATA messages
ship — this means the CRIME-style design's basic premise ("inject
chosen plaintext, observe encrypted size differences") cannot
accumulate enough probes against a single SSH session to converge.
The attacker effectively gets ONE shot per SSH session, and per-session
the fake cookie rotates, so probes can't be aggregated across sessions
either.

This is not a subtle bug or a config-tunable parameter — it's the
designed semantics of OpenSSH's x11-forward authentication path.

## What does *not* explain the behavior (ruled out)

- **`single_connection` mode** (channels.c:1916). The client always
  sends `single_connection = 0` in x11-req (channels.c:5413), so the
  listener does not auto-close after the first accept.
- **`ForwardX11Timeout` / `x11_refuse_time`** (channels.c:1379-1385,
  clientloop.c:1809-1813). Default timeout is 1200s; we observe
  clipping within seconds.
- **`session_close_single_x11`** (session.c:2298). Registered as
  cleanup only for the LISTENER channels in `s->x11_chanids[]`
  (session.c:2559-2562); not for per-connection x11-connection
  channels. Doesn't fire on each rejected connection.
- **Compression context resetting between channels.** zlib@openssh.com
  shares one zlib stream per direction across all channels (we
  empirically confirmed compression is active and the ratio is ~84%
  on a working SSH session). Compression isn't the problem.

## What this implies for the PoC

The original spec assumed many probes per session against a single
fake cookie. OpenSSH's x11-forward semantics make this impossible in
practice. To make the design viable, one of the following must
change:

1. **Use a different injection vector.** Any forwarded channel where
   the SSH client does NOT validate-and-reject the first bytes would
   work — `direct-tcpip` reverse forwards (`ssh -R`), forwarded SOCKS,
   etc. The `x11-req` cookie auth path is uniquely hostile.
2. **Modify or replace OpenSSH.** Patching out the `channel_force_close`
   on rejection (or at least the `sshbuf_reset(c->output)`) would
   keep the channel useful for measurement. Switching SSH
   implementation (AsyncSSH, libssh) might give different behavior.
3. **Send only ONE probe per fresh SSH session** and aggregate
   across sessions using a *known* (constant) target — but the fake
   cookie rotates per session, so there's no single target to converge
   on; aggregation only works for the SECURITY-extension cookie itself
   on the client side, which the spec explicitly rules out.

(The directions in `README.md`'s "What would unblock end-to-end
recovery" section reflect these.)
