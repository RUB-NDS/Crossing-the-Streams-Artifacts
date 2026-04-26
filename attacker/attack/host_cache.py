"""Resolve container hostnames to IPv4 addresses once at startup, cache
the result, and serve every subsequent caller from memory.

Why: Docker's embedded DNS resolver at 127.0.0.11 is a single shared
service per host. At ≥25 parallel attacker stacks, the per-measurement
hostname lookups (aiohttp client.post, asyncio.open_connection) saturate
it and start dropping UDP queries -- surfacing as
``ClientConnectorDNSError: [Temporary failure in name resolution]`` /
``socket.gaierror EAI_AGAIN``. Container IPs are stable for the
container's lifetime, so a single resolve is sufficient.

Contract: call ``resolve_once()`` once at startup (in mitm.py main).
After that, ``client_host()`` / ``client_base()`` return the cached IP
without ever touching the resolver. Calling them before
``resolve_once()`` raises -- a programming error, not a runtime fallback.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from urllib.parse import urlparse

LOG = logging.getLogger("attack.host_cache")

CLIENT_HOSTNAME: str = os.environ.get("CLIENT_HOST", "client")

# Extract the HTTP port from CLIENT_CONTROL_URL so docker-compose's
# existing env-var convention keeps working. We don't use the hostname
# from the URL -- CLIENT_HOST is the canonical source for that.
_default_url = f"http://{CLIENT_HOSTNAME}:8000"
_parsed = urlparse(os.environ.get("CLIENT_CONTROL_URL", _default_url))
CLIENT_HTTP_PORT: int = _parsed.port or 8000

_resolved: dict[str, str] = {}


async def resolve_once(
    hostname: str = CLIENT_HOSTNAME,
    retries: int = 30,
    delay: float = 1.0,
) -> str:
    """Resolve ``hostname`` to an IPv4 address and cache it.

    Idempotent: repeat calls for the same hostname return the cached IP
    without re-querying. Retries handle Docker's embedded DNS being slow
    or unavailable during the first seconds after container bring-up.
    """
    if hostname in _resolved:
        return _resolved[hostname]
    loop = asyncio.get_running_loop()
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            infos = await loop.getaddrinfo(
                hostname, None,
                family=socket.AF_INET, type=socket.SOCK_STREAM,
            )
            ip = infos[0][4][0]
            _resolved[hostname] = ip
            LOG.info("resolved %s -> %s (attempt %d)", hostname, ip, attempt)
            return ip
        except OSError as exc:
            last_exc = exc
            if attempt < retries:
                await asyncio.sleep(delay)
    raise RuntimeError(
        f"failed to resolve {hostname!r} after {retries} attempts: {last_exc}"
    )


def client_host() -> str:
    """Cached client IP. Must be preceded by ``resolve_once()`` in startup."""
    ip = _resolved.get(CLIENT_HOSTNAME)
    if ip is None:
        raise RuntimeError(
            f"host_cache.client_host() called before resolve_once({CLIENT_HOSTNAME!r}); "
            "wire host_cache.resolve_once() into startup before serving traffic"
        )
    return ip


def client_base() -> str:
    """Cached ``http://<client-ip>:<port>`` URL for HTTP control calls."""
    return f"http://{client_host()}:{CLIENT_HTTP_PORT}"
