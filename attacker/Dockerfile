FROM python:3.14-slim

# libpcap is optional for scapy on Linux (it can use AF_PACKET sockets
# directly with NET_RAW), but installing it lets scapy pick the most
# efficient backend.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates tcpdump libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY attacker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY attacker/mitm.py attacker/exploit.html attacker/exploit_pna.html ./

# The engine uses `from attacker.attack.*` imports, so we replicate the
# on-disk layout: /app/attacker/attack/. /app is on sys.path (it is the
# WORKDIR / the CMD's cwd).
RUN mkdir -p attacker
RUN touch attacker/__init__.py
COPY attacker/attack/ attacker/attack/

# Pin sibling-container hostnames in /etc/hosts at startup so the main
# process never queries Docker's embedded DNS resolver under burst load.
# See scripts/pin-hosts.sh for rationale.
COPY scripts/pin-hosts.sh /usr/local/bin/pin-hosts.sh
RUN chmod +x /usr/local/bin/pin-hosts.sh

ENTRYPOINT ["/usr/local/bin/pin-hosts.sh"]
CMD ["python", "/app/mitm.py"]
