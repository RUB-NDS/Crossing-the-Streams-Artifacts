FROM python:3.14-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssh-client \
        # Chromium runtime dependencies for the BEAST attack variant.
        libasound2t64 libatk-bridge2.0-0 libatk1.0-0 libcairo2 libcups2 \
        libdbus-1-3 libdrm2 libgbm1 libglib2.0-0 libnspr4 libnss3 \
        libpango-1.0-0 libx11-6 libxcb1 libxcomposite1 libxdamage1 \
        libxext6 libxfixes3 libxkbcommon0 libxrandr2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY client/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download Chromium (system deps already installed above).
RUN playwright install chromium

# Ansible config + playbook + inventory used by the Ansible attack
# variant.  ANSIBLE_CONFIG points Ansible at our config.
ENV ANSIBLE_CONFIG=/app/ansible/ansible.cfg
COPY client/ansible /app/ansible

COPY client/client.py .

CMD ["python", "/app/client.py"]
