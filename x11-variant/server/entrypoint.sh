#!/bin/bash
set -euo pipefail

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
fi

# Hand the victim's private key to whoever shares /srv/keys (the client).
chmod 0644 /srv/keys/victim_id_ed25519 /srv/keys/victim_id_ed25519.pub

/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config &
SSHD_PID=$!

# Engine HTTP service runs as the unprivileged 'attacker' user, but with
# CAP_NET_RAW preserved as an ambient capability so it can run scapy's
# AsyncSniffer on eth0. This is the PoC measurement relaxation documented
# in §2.1 of the spec — the rest of the user's capabilities (file ACLs,
# no sudo, no group membership in victim's groups) remain enforced.
cd /opt/attacker
exec setpriv \
    --reuid=attacker --regid=attacker --init-groups \
    --inh-caps=+net_raw \
    --ambient-caps=+net_raw \
    env HOME=/home/attacker PYTHONPATH=/opt python3 -u -m attacker.service
