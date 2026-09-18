# Artifact Evaluation Guide

*Crossing the Streams: SSH Plaintext Recovery via a Common Compression
Context in Multiplexed Channels*

This guide is for artifact reviewers. It describes four self-contained
scenarios: one attack per proof-of-concept, plus a reproduction of the
performance measurements in Table 3.

`README.md` remains the reference for the architecture, the HTTP control
surface, and the repository layout. This file only covers how to run the
artifact and what to do when a run does not reproduce.


## What the artifact claims

The paper describes an adaptive compression side-channel against SSH:
when several channels share one zlib compression context, an attacker who
can inject chosen plaintext into *any* channel can recover a secret
carried by *another* channel, by watching how well the shared compressor
compresses each guess. The artifact instantiates that attack in three
settings and measures its cost.

| Scenario | Paper | What the attacker controls | Recovered secret |
| :--- | :--- | :--- | :--- |
| Direct | 5.1 | Raw TCP to a network-exposed port forward | Redis `AUTH` password |
| Browser | 5.2 | A web page in the victim's browser | Redis `AUTH` password |
| Ansible | 5.3 | A fresh `ansible-playbook` run per guess | sudo (`become`) password |

In all three the recovered secret is `hunter2`, and the attacker stays a
passive on-path observer of the SSH stream: it never terminates,
decrypts, or modifies SSH. The client pins the real server's host key, so
an active in-the-middle attempt would be rejected at the SSH layer.


## Requirements

- Docker with Compose v2 (`docker compose`, not `docker-compose`).
- Python 3 on the host. Standard library only.
- About 8 GB RAM for the single stack. Scenario 4's `full` mode wants far
  more; see below.
- Roughly 6 GB of disk for the images. The client image includes a
  Playwright Firefox.

The scenario scripts call `python3`, falling back to `python`. The README
writes `python`, which on many systems is not on `PATH`; prefer `python3`
if you run the underlying scripts directly.


## Getting started (about 5 minutes)

```bash
docker compose up -d --build          # build and start the five services
./artifact-evaluation/scenario4_table3.sh    # recompute Table 3, no stack needed
```

The first command builds the images and starts keygen, Redis, the SSH
server, the attacker, and the client. The second reads the committed
measurement data and prints Table 3. Neither runs an attack, so together
they confirm the stack builds and the published numbers match the data
behind them.

To confirm the stack is actually wired up:

```bash
curl -s http://localhost:8000/status | python3 -m json.tool
```

Expect `ssh_connected: true`, `ssh_send_compression: zlib@openssh.com`,
`ssh_send_cipher: chacha20-poly1305@openssh.com`, and an active
`redis_tunnel`. The cipher matters: the alignment sweep assumes
ChaCha20-Poly1305's 8-byte padding granularity.


## The four scenarios

Each script brings the stack up if needed, checks preconditions, runs one
end-to-end recovery of `hunter2`, and prints PASS or FAIL. Extra
arguments are passed through to the underlying `scripts/verify_*.py`.

```bash
./artifact-evaluation/scenario1_direct.sh      # Section 5.1
./artifact-evaluation/scenario2_browser.sh     # Section 5.2
./artifact-evaluation/scenario3_ansible.sh     # Section 5.3
./artifact-evaluation/scenario4_table3.sh      # Table 3
```

| Scenario | Typical runtime | Default commit margin |
| :--- | ---: | ---: |
| 1, direct | 15-30 min | 80 |
| 2, browser | 25-45 min | 88 |
| 3, ansible | 5-15 min | 8 |
| 4, published | seconds | n/a |

Watch progress per byte while an attack runs:

```bash
docker compose logs -f attacker
```

Each committed byte prints a `recovered so far:` line. Start with
scenario 3: it is the fastest and the most reliable, because a fresh SSH
connection per guess means every measurement starts from an empty zlib
window.

### Scenario 4 in detail

Table 3 reports the guess count per recovered password for each
(scenario, noise-compensation configuration) pair, at the commit margin
where every trial recovered. The script has three modes:

```bash
./artifact-evaluation/scenario4_table3.sh              # published (default)
./artifact-evaluation/scenario4_table3.sh quick        # re-measure one cell
./artifact-evaluation/scenario4_table3.sh full         # the whole sweep
```

- **published** recomputes all 13 cells from the committed per-trial data
  under `evaluation/`, in about a second. This checks the paper's numbers
  against the measurements they came from.
- **quick** re-measures a single cell live with a reduced trial count.
  It defaults to ansible / AS+CE, the cheapest cell, and prints the
  published cell next to the fresh one. Tens of minutes.
- **full** runs `scripts/sweep_commit_margin.sh`, which produced
  `evaluation/`. This costs **days** of machine time and wants 25+
  parallel compose stacks. It writes to `results/`, never `evaluation/`.

Re-measuring every cell is not practical inside an evaluation window,
which is why the committed data is the primary artifact for Table 3 and
`quick` exists to spot-check it.


## Tuning the commit margin

**This is the one knob that decides whether a run reproduces.** If a
scenario returns a wrong password, this section is almost certainly why.

The commit margin (the paper's `mu`, Section 4.2) is how far ahead of the
runner-up the best candidate must be before the engine commits a byte.
The engine **never revisits a committed byte**. So if measurement noise
lets a wrong candidate reach the margin, that byte is wrong permanently,
and every later position inherits a corrupted known prefix.

The margin that works is a property of the host, not of the attack. It
depends on how much jitter the machine adds to the compressed-size
measurement. The repository's own sweep data shows how wide that
range is. These are the margins at which each cell first reached 100 %
recovery over 100 trials:

| Scenario | NO | FS | AS | CE | AS+CE |
| :--- | ---: | ---: | ---: | ---: | ---: |
| direct | 8 | 40 | 16 | 16 | **80** |
| browser | n/a | 48 | 64 | n/a | **88** |
| ansible | 8 | 8 | 8 | 8 | **8** |

The `verify_*.py` scripts run the adapter defaults, which select adaptive
alignment sweep plus candidate elimination, i.e. the **AS+CE** column.
Reproduce that column's margin and the scenarios are stable; run below it
and they are not. For reference, at `mu = 16` the committed direct AS+CE
run recovers 2 of 100 passwords, and at `mu = 64` the browser AS+CE run
recovers 48 of 100. The scenario scripts therefore default to 80, 88, and
8 rather than to the adapters' built-in 16, 64, and 8.

### Trying a different margin

Every verify script and every scenario script takes `--commit-margin`,
and honours the `AE_COMMIT_MARGIN` environment variable:

```bash
./artifact-evaluation/scenario1_direct.sh --commit-margin 96
AE_COMMIT_MARGIN=96 ./artifact-evaluation/scenario1_direct.sh

python3 scripts/verify_direct.py  --commit-margin 96
python3 scripts/verify_browser.py --commit-margin 104
python3 scripts/verify_ansible.py --commit-margin 16
```

If a run returns a wrong password, raise the margin by 8 and run it
again. That is exactly what `scripts/sweep_commit_margin.sh` automates,
in the same 8-byte steps. Raising the margin costs guesses roughly
linearly, so raise it until the recovery is stable and no further.

Two more knobs matter:

- `--fail-fast` sends the ground truth to the engine as `expected`, so it
  aborts on the first wrong byte instead of grinding on a corrupted
  prefix until `max_rounds`. The scenario scripts pass it by default. It
  turns a wasted hour into a wasted minute, and it tells you *which*
  byte went wrong.
- `scripts/verify_ansible.py` pins the alignment length the paper found
  winning (1) instead of sweeping all eight. If that assumption does not
  hold on your host, pass `--full-sweep`. It costs about 8x the guesses
  and assumes nothing.


## Troubleshooting

**A wrong password is recovered.** The commit margin is too low for this
host. See above. This is by far the most common failure, and it is not a
crash: the run completes and reports a confident, wrong answer.

**The attack appears to hang.** When a byte is committed wrongly, later
positions often cannot separate any candidate, so the margin stays at 0
and the engine grinds to `max_rounds` (128 by default). `docker compose
logs -f attacker` shows `margin=0` repeating with the alignment maxed
out. Use `--fail-fast` to abort at the first wrong byte instead.

**`POST /cancel` does not stop the attack.** Cancellation is only checked
at a byte boundary, so a position that never commits never sees it. To
recover:

```bash
docker compose restart attacker
curl -X POST http://localhost:8000/reset      # the client will not reconnect on its own
```

Restarting the attacker drops the TCP forwarder, which drops the client's
SSH connection; the client does not reconnect by itself, so the `/reset`
is required. Confirm with `/status` that `ssh_connected` is true again
before starting another run.

**`HTTP Error 409: Conflict` from a verify script.** The attacker runs
one attack at a time and a previous one is still in flight. Cancel it, or
restart as above.

**A run behaves differently from the one before it.** Reset between
measurements. A stack left over from an earlier run can be carrying a
wedged attack, a rotated secret, or a browser that dropped off. The
cheapest reset is `docker compose down && docker compose up -d`; the
images are cached, so it takes seconds.

**`python: command not found`.** Use `python3`, or the scenario scripts,
which detect it.

**The browser scenario reports `browser_connected: false`.** The client
launches headless Firefox at container start; give it a few seconds, or
`docker compose restart client`. Firefox is required, not Chromium or
WebKit: the exploit page is served from `http://attacker:9000` and beacons
to `http://localhost:6379`, a public-to-loopback request whose body
Chromium and WebKit drop under Private Network Access.

**`keys/` shows up as a local change.** It holds the Ed25519 host and
client keys the `keygen` service regenerates on every `up`. It is
git-ignored and must never be committed.


## What a reviewer can reasonably conclude

Running scenarios 1-3 shows that each proof-of-concept recovers the
secret end-to-end, through the transport the paper describes, with the
attacker never decrypting SSH. Running scenario 4 in `published` mode
shows that Table 3's numbers follow from the committed per-trial data;
`quick` mode spot-checks one cell against a fresh measurement.

What a reviewer cannot do in a normal evaluation window is re-measure all
13 cells: that is the `full` sweep, and it takes days. The guess counts
in Table 3 are also host-dependent in the same way the commit margin is,
so a fresh measurement should be expected to land in the same
neighbourhood rather than on the same number.
