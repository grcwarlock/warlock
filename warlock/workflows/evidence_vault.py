"""Evidence Vault — multi-backend binary evidence storage.

Supports three storage backends:
  - ``s3``    — Amazon S3 (requires boto3)
  - ``gcs``   — Google Cloud Storage (requires google-cloud-storage)
  - ``local`` — Local filesystem (development / air-gapped)

Configuration (environment variables):
  WLK_EVIDENCE_BACKEND  — "s3", "gcs", or "local" (default: "local")
  WLK_EVIDENCE_BUCKET   — bucket name for S3 or GCS
  WLK_EVIDENCE_PATH     — root path for local backend (default: "./evidence")

Usage::

    vault = EvidenceVault()

    # Store evidence for a finding
    url = vault.upload_evidence(
        finding_id="abc-123",
        file_bytes=b"...",
        filename="screenshot.png",
        content_type="image/png",
    )

    # Retrieve a time-limited access URL (or file path for local)
    access_url = vault.get_evidence("abc-123/screenshot.png")

    # List all evidence for a finding
    items = vault.list_evidence("abc-123")
"""

from __future__ import annotations

import logging
import os
import pathlib
import re
import uuid
from datetime import timedelta
from typing import Any

log = logging.getLogger(__name__)

# Default presigned URL expiry
_PRESIGNED_EXPIRY_SECONDS = 3600


def _get_backend() -> str:
    return os.environ.get("WLK_EVIDENCE_BACKEND", "local").lower().strip()


def _get_bucket() -> str:
    return os.environ.get("WLK_EVIDENCE_BUCKET", "")


def _get_path() -> str:
    return os.environ.get("WLK_EVIDENCE_PATH", "./evidence")


# ---------------------------------------------------------------------------
# EvidenceVault
# ---------------------------------------------------------------------------


class EvidenceVault:
    """Unified interface for evidence storage across S3, GCS, and local FS.

    The backend is selected at construction time via ``WLK_EVIDENCE_BACKEND``.
    All methods are synchronous; for high-throughput ingestion, call from a
    thread pool.
    """

    def __init__(
        self,
        backend: str | None = None,
        bucket: str | None = None,
        base_path: str | None = None,
    ) -> None:
        self.backend: str = (backend or _get_backend()).lower()
        self.bucket: str = bucket or _get_bucket()
        self.base_path: str = base_path or _get_path()

        if self.backend not in {"s3", "gcs", "local"}:
            raise ValueError(
                f"Unsupported evidence backend: '{self.backend}'. "
                "Choose 's3', 'gcs', or 'local'."
            )

        log.debug("EvidenceVault initialised: backend=%s", self.backend)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def upload_evidence(
        self,
        finding_id: str,
        file_bytes: bytes,
        filename: str,
        content_type: str = "application/octet-stream",
    ) -> str:
        """Upload evidence and return the evidence_id key.

        The evidence key is ``<finding_id>/<uuid>-<filename>`` so that
        multiple files per finding never collide.  Pass the returned key to
        :meth:`get_evidence` to obtain an access URL.

        For S3/GCS the returned value is the full ``s3://`` / ``gs://`` URI.
        For the local backend the returned value is the evidence_id key
        (relative path under base_path); use :meth:`get_evidence` to resolve
        it to an absolute path.

        Args:
            finding_id:    UUID or slug of the associated Finding record.
            file_bytes:    Raw file content.
            filename:      Original filename (used as a suffix in the key).
            content_type:  MIME type for S3/GCS metadata.

        Returns:
            The evidence_id key (S3/GCS URI or relative local path).
        """
        # Sanitize filename — strip path separators and null bytes
        safe_filename = re.sub(r'[/\\:\x00]', '_', filename)
        safe_filename = re.sub(r'\.\.', '_', safe_filename)  # prevent traversal
        if not re.match(r'^[\w\-. ]+$', safe_filename):
            safe_filename = re.sub(r'[^\w\-.]', '_', safe_filename)
        # Validate finding_id is UUID-like
        if not re.match(r'^[\w\-]+$', finding_id):
            raise ValueError(f"Invalid finding_id: {finding_id}")
        evidence_id = f"{finding_id}/{uuid.uuid4()}-{safe_filename}"

        dispatch = {
            "s3": self._upload_s3,
            "gcs": self._upload_gcs,
            "local": self._upload_local,
        }
        return dispatch[self.backend](evidence_id, file_bytes, content_type)

    def get_evidence(self, evidence_id: str) -> str:
        """Return a time-limited presigned URL (S3/GCS) or file path (local).

        Args:
            evidence_id: The key returned by :meth:`upload_evidence`
                         (i.e. ``<finding_id>/<uuid>-<filename>``).

        Returns:
            Presigned HTTPS URL valid for one hour, or an absolute path for
            the local backend.
        """
        dispatch = {
            "s3": self._presign_s3,
            "gcs": self._presign_gcs,
            "local": self._path_local,
        }
        return dispatch[self.backend](evidence_id)

    def list_evidence(self, finding_id: str) -> list[dict[str, Any]]:
        """Return metadata for every evidence file stored for *finding_id*.

        Args:
            finding_id: UUID or slug of the Finding to list.

        Returns:
            List of dicts with keys ``evidence_id``, ``url`` and ``backend``.
        """
        dispatch = {
            "s3": self._list_s3,
            "gcs": self._list_gcs,
            "local": self._list_local,
        }
        return dispatch[self.backend](finding_id)

    # ------------------------------------------------------------------
    # S3 backend
    # ------------------------------------------------------------------

    def _s3_client(self) -> Any:
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "boto3 is required for the S3 evidence backend. "
                "Install it with: pip install boto3"
            ) from exc
        return boto3.client("s3")

    def _upload_s3(self, evidence_id: str, body: bytes, content_type: str) -> str:
        client = self._s3_client()
        client.put_object(
            Bucket=self.bucket,
            Key=evidence_id,
            Body=body,
            ContentType=content_type,
        )
        url = f"s3://{self.bucket}/{evidence_id}"
        log.info("Evidence uploaded to S3: %s", url)
        return url

    def _presign_s3(self, evidence_id: str) -> str:
        client = self._s3_client()
        url: str = client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": evidence_id},
            ExpiresIn=_PRESIGNED_EXPIRY_SECONDS,
        )
        return url

    def _list_s3(self, finding_id: str) -> list[dict[str, Any]]:
        client = self._s3_client()
        prefix = f"{finding_id}/"
        paginator = client.get_paginator("list_objects_v2")
        items: list[dict[str, Any]] = []
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key: str = obj["Key"]
                items.append(
                    {
                        "evidence_id": key,
                        "url": self._presign_s3(key),
                        "backend": "s3",
                    }
                )
        return items

    # ------------------------------------------------------------------
    # GCS backend
    # ------------------------------------------------------------------

    def _gcs_client(self) -> Any:
        try:
            from google.cloud import storage as gcs  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "google-cloud-storage is required for the GCS evidence backend. "
                "Install it with: pip install google-cloud-storage"
            ) from exc
        return gcs.Client()

    def _upload_gcs(self, evidence_id: str, body: bytes, content_type: str) -> str:
        client = self._gcs_client()
        bucket = client.bucket(self.bucket)
        blob = bucket.blob(evidence_id)
        blob.upload_from_string(body, content_type=content_type)
        url = f"gs://{self.bucket}/{evidence_id}"
        log.info("Evidence uploaded to GCS: %s", url)
        return url

    def _presign_gcs(self, evidence_id: str) -> str:
        client = self._gcs_client()
        bucket = client.bucket(self.bucket)
        blob = bucket.blob(evidence_id)
        url: str = blob.generate_signed_url(
            expiration=timedelta(seconds=_PRESIGNED_EXPIRY_SECONDS),
            method="GET",
        )
        return url

    def _list_gcs(self, finding_id: str) -> list[dict[str, Any]]:
        client = self._gcs_client()
        prefix = f"{finding_id}/"
        blobs = client.list_blobs(self.bucket, prefix=prefix)
        items: list[dict[str, Any]] = []
        for blob in blobs:
            items.append(
                {
                    "evidence_id": blob.name,
                    "url": self._presign_gcs(blob.name),
                    "backend": "gcs",
                }
            )
        return items

    # ------------------------------------------------------------------
    # Local filesystem backend
    # ------------------------------------------------------------------

    def _resolve_local(self, evidence_id: str) -> pathlib.Path:
        root = pathlib.Path(self.base_path).resolve()
        target = (root / evidence_id).resolve()
        # Prevent path traversal: target must be within root
        target.relative_to(root)
        return target

    def _upload_local(self, evidence_id: str, body: bytes, _content_type: str) -> str:
        target = self._resolve_local(evidence_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        log.info("Evidence stored locally: %s", target)
        # Return the relative evidence_id so callers can pass it back to
        # get_evidence(), matching the S3/GCS convention of returning a key.
        return evidence_id

    def _path_local(self, evidence_id: str) -> str:
        return str(self._resolve_local(evidence_id))

    def _list_local(self, finding_id: str) -> list[dict[str, Any]]:
        root = pathlib.Path(self.base_path).resolve()
        prefix_dir = root / finding_id
        if not prefix_dir.exists():
            return []
        items: list[dict[str, Any]] = []
        for entry in sorted(prefix_dir.iterdir()):
            if entry.is_file():
                evidence_id = f"{finding_id}/{entry.name}"
                items.append(
                    {
                        "evidence_id": evidence_id,
                        "url": str(entry),
                        "backend": "local",
                    }
                )
        return items
