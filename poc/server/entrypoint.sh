#!/bin/sh
set -eu

# Host key comes from the shared /keys volume populated by the keygen
# one-shot container.
cp /keys/server_host_key /etc/ssh/server_host_key
chmod 600 /etc/ssh/server_host_key

# victim user: pubkey login using the client's generated key.
mkdir -p /home/victim/.ssh
cp /keys/client_user_key.pub /home/victim/.ssh/authorized_keys
chmod 700 /home/victim/.ssh
chmod 600 /home/victim/.ssh/authorized_keys
chown -R victim:victim /home/victim/.ssh

# root user: same key, used by the client to rotate the victim's sudo
# password between test runs via `chpasswd` over SSH.
mkdir -p /root/.ssh
cp /keys/client_user_key.pub /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

echo "[server] starting sshd"
exec /usr/sbin/sshd -D -e
