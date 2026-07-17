FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates golang-go \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin
RUN GOBIN=/usr/local/bin go install github.com/google/osv-scanner/cmd/osv-scanner@latest
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin
RUN GOBIN=/usr/local/bin go install github.com/gitleaks/gitleaks/v8@latest

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY api /app/api
COPY worker /app/worker
COPY scripts /app/scripts
RUN pip install --no-cache-dir -e . semgrep

RUN useradd --create-home --shell /usr/sbin/nologin watchtower \
    && chown -R watchtower:watchtower /app
USER watchtower
