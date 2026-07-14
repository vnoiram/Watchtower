FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY api /app/api
COPY migrations /app/migrations
RUN pip install --no-cache-dir -e .
EXPOSE 8000
