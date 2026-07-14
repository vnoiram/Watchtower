from __future__ import annotations

import hashlib
from pathlib import Path

import boto3

from api.app.config import Settings


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact_key(repository_id: str, application_id: str, scan_id: str, filename: str) -> str:
    return f"repositories/{repository_id}/applications/{application_id}/scans/{scan_id}/{filename}"


class ArtifactStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.client = boto3.client(
            "s3",
            endpoint_url=settings.minio_endpoint,
            aws_access_key_id=settings.minio_access_key,
            aws_secret_access_key=settings.minio_secret_key,
        )

    def ensure_bucket(self) -> None:
        buckets = self.client.list_buckets().get("Buckets", [])
        if not any(bucket["Name"] == self.settings.minio_bucket for bucket in buckets):
            self.client.create_bucket(Bucket=self.settings.minio_bucket)

    def put_file(self, key: str, path: Path) -> str:
        data = path.read_bytes()
        self.ensure_bucket()
        self.client.put_object(Bucket=self.settings.minio_bucket, Key=key, Body=data)
        return sha256_bytes(data)

