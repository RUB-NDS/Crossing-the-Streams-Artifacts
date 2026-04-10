FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

# Create the victim user (pubkey auth only, no password).
# passwd -d unlocks the account so sshd allows pubkey login.
RUN useradd -m -s /bin/sh victim \
 && passwd -d victim

COPY server/sshd_config /etc/ssh/sshd_config
COPY server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
