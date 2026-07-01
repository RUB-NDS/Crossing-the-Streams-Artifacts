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
# Chromium for browser_pna is pinned via playwright==1.61.0
# (client/requirements.txt) -> Chromium 149 (Chrome for Testing; same Blink /
# networking stack). This is the current Chromium-142+ "Local Network Access"
# (LNA) era that replaced Private Network Access preflights -- which the paper
# (Section 5.2) targets. On a real headed browser LNA gates a page->loopback
# fetch behind a one-time permission prompt; client.py::launch_chromium grants
# that permission best-effort (simulating the victim's "Allow"). In the
# automated headless harness LNA does not actively block, so the guess rides in
# the CORS OPTIONS preflight that exploit_pna.html forces (see launch_chromium /
# README). Nothing here disables LNA/CORS. We use the default fast headless
# shell; the full channel="chromium" build starts far slower without changing
# the outcome.
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
