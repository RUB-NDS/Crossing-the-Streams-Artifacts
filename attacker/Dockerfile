FROM python:3.14-slim

# tcpdump is handy for ad-hoc inspection.  libpcap is optional for
# scapy on Linux (it can use AF_PACKET sockets directly with NET_RAW),
# but we install it so scapy can pick the most efficient backend.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates tcpdump libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mitm.py exploit.html ./

# New unified engine package.  The engine uses `from attacker.attack.*`
# imports, so we replicate the on-disk layout: /app/attacker/attack/.
# /app is already on sys.path (it is the WORKDIR / the CMD's cwd).
RUN mkdir -p attacker
RUN touch attacker/__init__.py
COPY attack/ attacker/attack/

CMD ["python", "/app/mitm.py"]
