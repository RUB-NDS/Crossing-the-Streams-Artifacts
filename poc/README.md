# Ansible `become` password recovery

Proof of concept demonstrating a compression side-channel against SSH
(RFC 4253 §6.2) that recovers an Ansible `become` sudo password from
encrypted traffic.

## Vulnerability

SSH uses a single zlib compression context per direction across all
channels on a transport.  When `ansible-playbook` runs with `become: yes`
over an SSH connection that also carries a `LocalForward`, a passive
on-path observer can inject chosen plaintext through the forwarded port
and observe ciphertext lengths.  A correct guess produces an LZ77 match
against the recently-compressed sudo password and compresses shorter,
leaking one byte per measurement.

The PoC plants the password `hunter2` and recovers it end-to-end.

## Preconditions

- **SSH compression enabled.**  Ansible's default `ssh_args` includes
  `-C`, enabling zlib compression on the transport.

- **Passive on-path position.**  The attacker can observe encrypted
  packet lengths on the wire.  No decryption or modification of SSH
  traffic is required.

- **Chosen-plaintext injection** into the client-to-server direction of
  the same SSH transport that carries the sudo password.  Any channel
  on the transport shares the zlib context (RFC 4253 §6.2).  Possible
  vectors include:

  - *Forwarded port (this PoC).*  The SSH connection inherits a
    `LocalForward` from the user's `~/.ssh/config`.  The attacker
    connects to the forwarded port, which opens a `direct-tcpip`
    channel in the shared zlib context.

  - *BEAST-style browser injection.*  Even when the forwarded port is
    bound to `localhost`, an attacker who can run JavaScript in the
    victim's browser (e.g. via a malicious ad or XSS) can reach it
    with cross-origin requests like `navigator.sendBeacon()`.  Named
    after the analogous TLS attack where the victim's browser serves
    as a chosen-plaintext oracle.

  - *Attacker-influenced task content.*  A playbook that uploads data
    derived from an external source — e.g. a `template` rendering
    variables from a compromised CMDB, or a `copy` deploying an
    artifact from an attacker-controlled registry — sends those bytes
    client-to-server through the same zlib context.

## Running

```bash
docker compose up -d --build
python run_poc.py
docker compose down
```

Expected output:

```
  Expected:  hunter2
  Recovered: hunter2
  Status:    PASS
```

Requires Docker, Docker Compose, and Python 3 (stdlib only) on the host.

## How it works

The attack runs in two phases:

1. **Length recovery.**  The 8-byte `SSH_MSG_CHANNEL_DATA` header
   preceding the password is fully predictable except for one length
   byte.  The attacker guesses it by measuring which value compresses
   shorter.

2. **Password recovery.**  With the full 9-byte prefix known, each
   password byte is recovered by sweeping candidate characters.  The
   correct character matches in zlib's sliding window and compresses
   1 byte shorter.  Noise bytes (DEFLATE 8-bit fixed-Huffman literals)
   push this 1-byte gain across chacha20-poly1305's 8-byte padding
   boundary, making it visible as a wire-length difference.

Each guess uses a fresh SSH connection (no multiplexing) so the zlib
context starts clean and the session channel ID is always 0.

## Architecture

Four containers on a Docker bridge network:

| Service    | Role |
| ---------- | ---- |
| `server`   | sshd + sudo — the Ansible target host |
| `client`   | Runs `ansible-playbook` with `become: yes` on request |
| `attacker` | Passive TCP relay + scapy sniffer + attack logic |
| `target`   | TCP drain — destination of the victim's `LocalForward` |

The client connects to the SSH server *through* the attacker's TCP relay,
giving the attacker visibility into encrypted packet lengths.  The
server's host key is pinned on the client — the attacker cannot tamper
with SSH.  The relay is a PoC simplification — a real on-path attacker
would passively observe packets without proxying (e.g. port mirror, ARP
spoofing, a compromised network hop, or wireless frame capture in
physical proximity).

## Disclaimer

Parts of this proof of concept were developed with assistance from
[Claude Code](https://claude.ai/code) (Anthropic).
