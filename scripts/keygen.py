"""Idempotently generate the SSH host key and client user key.

Both files end up in /keys, which is mounted into the server (read-only,
needs the host key + the authorized client public key) and the client
(read-only, needs the client private key + the server's public key for
known_hosts pinning).
"""

import os
import stat
import sys

import asyncssh

KEYS_DIR = "/keys"
HOST_KEY_PATH = os.path.join(KEYS_DIR, "server_host_key")
CLIENT_KEY_PATH = os.path.join(KEYS_DIR, "client_user_key")


def ensure_key(path: str, label: str) -> None:
    if os.path.exists(path):
        print(f"[keygen] {label} already exists at {path}", flush=True)
        return
    print(f"[keygen] generating {label} at {path}", flush=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(path)
    key.write_public_key(path + ".pub")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(path + ".pub", stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)


def main() -> int:
    os.makedirs(KEYS_DIR, exist_ok=True)
    ensure_key(HOST_KEY_PATH, "server host key")
    ensure_key(CLIENT_KEY_PATH, "client user key")
    print("[keygen] done.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
