FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

# Victim user with an initially empty password so pubkey login works.
# The real sudo password is set at runtime by the client via chpasswd.
RUN useradd -m -s /bin/bash victim \
 && passwd -d victim

# victim must provide a password to sudo -- that's our attack target.
RUN echo 'victim ALL=(ALL:ALL) ALL' > /etc/sudoers.d/victim \
 && chmod 440 /etc/sudoers.d/victim

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
