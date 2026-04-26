FROM python:3.14-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY client/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Firefox runtime libs are managed by Playwright's own manifest — we
# let `--with-deps` apt-install them rather than hand-curating a list.
RUN playwright install --with-deps firefox \
 && rm -rf /var/lib/apt/lists/*

ENV ANSIBLE_CONFIG=/app/ansible/ansible.cfg
COPY client/ansible /app/ansible

COPY client/client.py .

# Pin sibling-container hostnames in /etc/hosts at startup so ssh and
# every other subprocess never queries Docker's embedded DNS resolver
# (127.0.0.11) under burst load. See scripts/pin-hosts.sh for rationale.
COPY scripts/pin-hosts.sh /usr/local/bin/pin-hosts.sh
RUN chmod +x /usr/local/bin/pin-hosts.sh

ENTRYPOINT ["/usr/local/bin/pin-hosts.sh"]
CMD ["python", "/app/client.py"]
