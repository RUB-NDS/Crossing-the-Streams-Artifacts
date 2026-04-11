FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

# Create the victim user.  The account initially has no password so sshd
# allows pubkey login; the client (running as root over SSH) sets the
# sudo password at runtime via `chpasswd` once the stack is up.
RUN useradd -m -s /bin/bash victim \
 && passwd -d victim

# Grant victim passworded sudo (the whole point of the Ansible variant:
# we're attacking the password that `become: yes` sends over stdin).
RUN echo 'victim ALL=(ALL:ALL) ALL' > /etc/sudoers.d/victim \
 && chmod 440 /etc/sudoers.d/victim

COPY server/sshd_config /etc/ssh/sshd_config
COPY server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]
