FROM python:3.11-slim

WORKDIR /app

# Network-recon and execution tools needed by asset_discovery and execution handler.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
        dnsutils \
        whois \
        nmap \
        iproute2 \
        tcpdump \
        iptables \
        docker-cli \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps before copying code so this layer is cached across
# code-only changes (the expensive step stays in cache).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1 \
    LOG_LEVEL=INFO

CMD ["python", "main.py"]
