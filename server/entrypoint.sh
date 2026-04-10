#!/bin/sh
set -eu

# Copy host key from shared volume
cp /keys/server_host_key /etc/ssh/server_host_key
chmod 600 /etc/ssh/server_host_key

# Set up authorized_keys for the victim user
mkdir -p /home/victim/.ssh
cp /keys/client_user_key.pub /home/victim/.ssh/authorized_keys
chmod 700 /home/victim/.ssh
chmod 600 /home/victim/.ssh/authorized_keys
chown -R victim:victim /home/victim/.ssh

echo "[server] starting sshd (Compression yes, AllowTcpForwarding yes)"
exec /usr/sbin/sshd -D -e
