FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl docker.io \
    && rm -rf /var/lib/apt/lists/*

ARG COMPOSE_VERSION=2.29.7
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in x86_64) DARCH=x86_64 ;; aarch64|arm64) DARCH=aarch64 ;; *) echo "unsupported arch: $ARCH"; exit 1 ;; esac; \
    mkdir -p /root/.docker/cli-plugins; \
    curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${DARCH}" \
      -o /root/.docker/cli-plugins/docker-compose; \
    chmod +x /root/.docker/cli-plugins/docker-compose

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sensability ./sensability
COPY subnets.txt ./subnets.txt

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "sensability"]
