#!/bin/bash
set -euo pipefail

# Start Xvfb with SECURITY extension explicitly enabled (required for
# `ssh -X`'s untrusted xauth generate path).
Xvfb :0 -screen 0 1024x768x24 +extension SECURITY &
XVFB_PID=$!

export DISPLAY=:0
# Wait for Xvfb to be ready.
for _ in $(seq 1 30); do
    if xdpyinfo -display :0 >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
XDPY_INFO=$(xdpyinfo -display :0)
if ! echo "$XDPY_INFO" | grep -q SECURITY; then
    echo "FATAL: SECURITY extension not present on Xvfb"
    exit 1
fi

# Provision the victim's SSH key from the shared volume.
mkdir -p /home/victim/.ssh
cp /srv/keys/victim_id_ed25519 /home/victim/.ssh/id_ed25519
chmod 0600 /home/victim/.ssh/id_ed25519
chown -R victim:victim /home/victim/.ssh

# Pre-populate the local Xauthority for the victim user (so xauth list
# returns something for ssh -X to consume).
su victim -c 'xauth -f /home/victim/.Xauthority generate :0 . trusted' \
    || su victim -c 'xauth -f /home/victim/.Xauthority add :0 . $(mcookie)'

# Hand off to the harness as victim.
exec su victim -c 'DISPLAY=:0 PYTHONPATH=/opt python3 -u -m harness'
