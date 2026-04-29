#!/bin/sh
set -eu

cp /keys/server_host_key /etc/ssh/server_host_key
chmod 600 /etc/ssh/server_host_key

mkdir -p /home/victim/.ssh
cp /keys/client_user_key.pub /home/victim/.ssh/authorized_keys
chmod 700 /home/victim/.ssh
chmod 600 /home/victim/.ssh/authorized_keys
chown -R victim:victim /home/victim/.ssh

# The PoC client uses a root SSH login to rotate the victim's sudo password
# between attack runs (see /set_sudo_secret in client.py). Same key as the
# victim, different authorized_keys file.
mkdir -p /root/.ssh
cp /keys/client_user_key.pub /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

echo "[server] starting sshd"
exec /usr/sbin/sshd -D -e
