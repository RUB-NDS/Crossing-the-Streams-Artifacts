FROM python:3.14-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV ANSIBLE_CONFIG=/app/ansible/ansible.cfg
COPY ansible /app/ansible
COPY client.py .

CMD ["python", "/app/client.py"]
