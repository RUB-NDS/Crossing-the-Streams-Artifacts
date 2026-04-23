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

CMD ["python", "/app/client.py"]
