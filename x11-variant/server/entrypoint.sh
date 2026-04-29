#!/bin/bash
set -euo pipefail

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
fi

# Hand the victim's private key to whoever shares /srv/keys (the client).
chmod 0644 /srv/keys/victim_id_ed25519 /srv/keys/victim_id_ed25519.pub

/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config &
SSHD_PID=$!

# Engine HTTP service runs as the unprivileged 'attacker' user.
exec su attacker -c '
    cd /opt/attacker
    PYTHONPATH=/opt python3 -u -m attacker.service
'
