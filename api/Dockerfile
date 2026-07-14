FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md /app/
RUN pip install --no-cache-dir -e .
COPY api /app/api
COPY migrations /app/migrations
EXPOSE 8000

