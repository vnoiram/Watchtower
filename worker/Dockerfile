FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY api /app/api
COPY worker /app/worker
COPY scripts /app/scripts
RUN pip install --no-cache-dir -e .
