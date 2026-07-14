FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md /app/
RUN pip install --no-cache-dir -e .
COPY api /app/api
COPY worker /app/worker
COPY scripts /app/scripts

