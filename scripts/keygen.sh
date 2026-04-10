#!/bin/sh
set -eu

KEYS_DIR="/keys"
HOST_KEY="$KEYS_DIR/server_host_key"
CLIENT_KEY="$KEYS_DIR/client_user_key"

if [ ! -f "$HOST_KEY" ]; then
    echo "[keygen] generating server host key"
    ssh-keygen -t ed25519 -f "$HOST_KEY" -N "" -C ""
else
    echo "[keygen] server host key already exists"
fi

if [ ! -f "$CLIENT_KEY" ]; then
    echo "[keygen] generating client user key"
    ssh-keygen -t ed25519 -f "$CLIENT_KEY" -N "" -C ""
else
    echo "[keygen] client user key already exists"
fi

chmod 600 "$HOST_KEY" "$CLIENT_KEY"
chmod 644 "$HOST_KEY.pub" "$CLIENT_KEY.pub"
echo "[keygen] done."
