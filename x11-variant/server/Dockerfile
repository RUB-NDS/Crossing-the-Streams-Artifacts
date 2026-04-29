FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        xauth \
        x11-xserver-utils \
        iproute2 \
        python3 \
        python3-aiohttp \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash victim \
    && chmod 0700 /home/victim \
    && useradd -m -s /bin/bash attacker \
    && usermod -p '*' victim \
    && usermod -p '*' attacker

# Generate the per-build SSH key for victim and place public key in
# authorized_keys. Private key gets exported into /srv/keys for the
# client to mount-share.
RUN mkdir -p /home/victim/.ssh /srv/keys \
    && ssh-keygen -t ed25519 -N "" -f /srv/keys/victim_id_ed25519 -C "victim@x11-fwd-poc" \
    && cp /srv/keys/victim_id_ed25519.pub /home/victim/.ssh/authorized_keys \
    && chown -R victim:victim /home/victim/.ssh \
    && chmod 0700 /home/victim/.ssh \
    && chmod 0600 /home/victim/.ssh/authorized_keys

RUN mkdir -p /var/run/sshd /opt/attacker
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Server-side attacker package goes in /opt so PYTHONPATH=/opt finds it.
# (Filled in by Task 12 — this COPY is intentionally there now so the
#  layer cache invalidates correctly when the engine code changes.)
COPY attacker /opt/attacker

EXPOSE 22 9000
ENTRYPOINT ["/entrypoint.sh"]
