FROM python:3.14-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY client/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Firefox (browser scenario) + Chromium (browser_pna scenario). Runtime libs are
# managed by Playwright's own manifest -- we let `--with-deps` apt-install them
# rather than hand-curating a list.
#
# Chromium is PINNED via playwright==1.55.0 (client/requirements.txt), which
# bundles Chromium 140.0.7339.16. This build is chosen deliberately for the
# browser_pna scenario:
#   * It is PRE-142, so it has NO Chromium-142 "Local Network Access" one-time
#     permission prompt (which a headless browser cannot satisfy and would
#     auto-deny, killing the loopback fetch).
#   * It implements Private Network Access preflights: a cross-origin
#     private-origin -> loopback fetch is answered with an OPTIONS preflight
#     (PrivateNetworkAccessSendPreflights is default-on since M104), which is
#     exactly the vehicle browser_pna rides the guess in.
# Do NOT bump Playwright to 1.56+/Chromium 141+ without re-validating: 141 has a
# staged LNA rollout that can auto-deny loopback in headless, and 142 enforces
# the prompt. See README.md (browser_pna) and attacker/attack/adapters/browser_pna.py.
RUN playwright install --with-deps firefox chromium \
 && rm -rf /var/lib/apt/lists/*

ENV ANSIBLE_CONFIG=/app/ansible/ansible.cfg
COPY client/ansible /app/ansible

COPY client/client.py .

# Pin sibling-container hostnames in /etc/hosts at startup so ssh and every
# other subprocess never queries Docker's embedded DNS resolver under burst
# load. See scripts/pin-hosts.sh for rationale.
COPY scripts/pin-hosts.sh /usr/local/bin/pin-hosts.sh
RUN chmod +x /usr/local/bin/pin-hosts.sh

ENTRYPOINT ["/usr/local/bin/pin-hosts.sh"]
CMD ["python", "/app/client.py"]
