"""Cloud-agnostic object storage abstraction.

Supports:
- Local filesystem (dev/on-prem)
- S3-compatible API (AWS, GCS, Alibaba, DigitalOcean, MinIO, OVH, etc.)
- Azure Blob Storage

The interface is intentionally minimal: put, get, list, delete, exists.
Parquet files don't care where they live.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

log = logging.getLogger(__name__)


@runtime_checkable
class ObjectStorage(Protocol):
    """Protocol for cloud-agnostic object storage."""

    def put(self, path: str, data: bytes) -> None: ...
    def get(self, path: str) -> bytes: ...
    def list(self, prefix: str) -> list[str]: ...
    def delete(self, path: str) -> None: ...
    def exists(self, path: str) -> bool: ...


class LocalStorage:
    """Local filesystem storage backend for dev and on-prem."""

    def __init__(self, base_path: str) -> None:
        self._base = Path(base_path)
        self._base.mkdir(parents=True, exist_ok=True)

    def put(self, path: str, data: bytes) -> None:
        full = self._base / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(data)

    def get(self, path: str) -> bytes:
        full = self._base / path
        if not full.exists():
            raise FileNotFoundError(f"Object not found: {path}")
        return full.read_bytes()

    def list(self, prefix: str) -> list[str]:
        target = self._base / prefix
        if not target.exists():
            return []
        results = []
        for p in target.rglob("*"):
            if p.is_file():
                results.append(str(p.relative_to(self._base)))
        return sorted(results)

    def delete(self, path: str) -> None:
        full = self._base / path
        if full.exists():
            full.unlink()

    def exists(self, path: str) -> bool:
        return (self._base / path).exists()


class S3Storage:
    """S3-compatible object storage backend.

    Works with: AWS S3, GCS (interop), Alibaba OSS, DigitalOcean Spaces,
    MinIO, OVH, Huawei OBS, and any S3-compatible API.
    """

    def __init__(self, bucket_url: str, region: str = "") -> None:
        import boto3

        self._bucket_url = bucket_url
        parts = bucket_url.replace("s3://", "").split("/", 1)
        self._bucket = parts[0]
        self._prefix = parts[1] if len(parts) > 1 else ""
        kwargs: dict = {}
        if region:
            kwargs["region_name"] = region
        endpoint = os.environ.get("WLK_S3_ENDPOINT_URL", "")
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        self._client = boto3.client("s3", **kwargs)

    def _full_key(self, path: str) -> str:
        return f"{self._prefix}/{path}" if self._prefix else path

    def put(self, path: str, data: bytes) -> None:
        self._client.put_object(Bucket=self._bucket, Key=self._full_key(path), Body=data)

    def get(self, path: str) -> bytes:
        try:
            resp = self._client.get_object(Bucket=self._bucket, Key=self._full_key(path))
            return resp["Body"].read()
        except self._client.exceptions.NoSuchKey:
            raise FileNotFoundError(f"Object not found: {path}")

    def list(self, prefix: str) -> list[str]:
        full_prefix = self._full_key(prefix)
        results = []
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=full_prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if self._prefix:
                    key = key[len(self._prefix) + 1 :]
                results.append(key)
        return sorted(results)

    def delete(self, path: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=self._full_key(path))

    def exists(self, path: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=self._full_key(path))
            return True
        except Exception:
            return False


class AzureBlobStorage:
    """Azure Blob Storage backend."""

    def __init__(self, container_url: str) -> None:
        from azure.storage.blob import ContainerClient

        self._client = ContainerClient.from_container_url(container_url)

    def put(self, path: str, data: bytes) -> None:
        self._client.upload_blob(path, data, overwrite=True)

    def get(self, path: str) -> bytes:
        try:
            blob = self._client.download_blob(path)
            return blob.readall()
        except Exception:
            raise FileNotFoundError(f"Object not found: {path}")

    def list(self, prefix: str) -> list[str]:
        return sorted(b.name for b in self._client.list_blobs(name_starts_with=prefix))

    def delete(self, path: str) -> None:
        self._client.delete_blob(path)

    def exists(self, path: str) -> bool:
        try:
            self._client.get_blob_properties(path)
            return True
        except Exception:
            return False


def create_storage(
    backend: str, path: str = "lake", url: str = "", region: str = ""
) -> ObjectStorage:
    """Factory for creating storage backends from config."""
    if backend == "local":
        return LocalStorage(path)
    elif backend == "s3":
        if not url:
            raise ValueError("WLK_LAKE_STORAGE_URL required for S3 backend")
        return S3Storage(url, region)
    elif backend == "azure":
        if not url:
            raise ValueError("WLK_LAKE_STORAGE_URL required for Azure backend")
        return AzureBlobStorage(url)
    else:
        raise ValueError(f"Unknown storage backend: {backend}")
