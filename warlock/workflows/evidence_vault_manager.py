"""Evidence Vault Manager — document lifecycle management.

Provides upload, versioning, tagging, expiry tracking, and staleness
detection for evidence documents. Evidence artifacts are stored as
metadata records in the database, with content hashes for integrity.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


@dataclass
class EvidenceDocument:
    """Metadata for an evidence document in the vault."""

    id: str
    filename: str
    content_hash: str
    size_bytes: int
    version: int
    control_id: str | None = None
    framework: str | None = None
    tags: list[str] = field(default_factory=list)
    uploaded_by: str = ""
    uploaded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    description: str = ""
    mime_type: str = ""
    previous_version_id: str | None = None


@dataclass
class EvidenceVersion:
    """A specific version of an evidence document."""

    version: int
    content_hash: str
    size_bytes: int
    uploaded_by: str
    uploaded_at: datetime
    description: str = ""


class EvidenceVaultManager:
    """Manages evidence document lifecycle in the vault.

    Uses the saved_queries table (query_type='evidence_vault') for
    document metadata storage in the OLTP database.
    """

    QUERY_TYPE = "evidence_vault"

    def __init__(self, session) -> None:
        self._session = session

    def upload(
        self,
        filename: str,
        content: bytes | None = None,
        file_path: str | None = None,
        control_id: str | None = None,
        framework: str | None = None,
        tags: list[str] | None = None,
        uploaded_by: str = "cli@warlock",
        expires_days: int | None = None,
        description: str = "",
        mime_type: str = "",
    ) -> EvidenceDocument:
        """Upload a new evidence document or new version of existing.

        If a document with the same filename exists, creates a new version.
        Content is hashed for integrity but stored externally (filesystem / S3).
        """
        from warlock.db.models import SavedQuery

        # Compute hash from content or file
        if content is not None:
            content_hash = hashlib.sha256(content).hexdigest()
            size_bytes = len(content)
        elif file_path is not None:
            p = Path(file_path)
            if not p.exists():
                raise FileNotFoundError(f"Evidence file not found: {file_path}")
            data = p.read_bytes()
            content_hash = hashlib.sha256(data).hexdigest()
            size_bytes = len(data)
            if not filename:
                filename = p.name
        else:
            raise ValueError("Either content or file_path must be provided")

        # Check for existing document with same filename
        existing = (
            self._session.query(SavedQuery)
            .filter(
                SavedQuery.query_type == self.QUERY_TYPE,
                SavedQuery.name == filename,
            )
            .order_by(SavedQuery.created_at.desc())
            .first()
        )

        version = 1
        previous_version_id = None
        if existing:
            params = existing.parameters or {}
            version = (params.get("version", 1)) + 1
            previous_version_id = existing.id

        expires_at = None
        if expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

        doc_id = str(uuid4())
        doc = EvidenceDocument(
            id=doc_id,
            filename=filename,
            content_hash=content_hash,
            size_bytes=size_bytes,
            version=version,
            control_id=control_id,
            framework=framework,
            tags=tags or [],
            uploaded_by=uploaded_by,
            uploaded_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            description=description,
            mime_type=mime_type or self._guess_mime(filename),
            previous_version_id=previous_version_id,
        )

        # Store as SavedQuery record
        record = SavedQuery(
            id=doc_id,
            name=filename,
            description=description,
            sql_text="",  # Not a real query — metadata record
            query_type=self.QUERY_TYPE,
            parameters={
                "content_hash": content_hash,
                "size_bytes": size_bytes,
                "version": version,
                "control_id": control_id,
                "framework": framework,
                "tags": tags or [],
                "uploaded_by": uploaded_by,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "mime_type": doc.mime_type,
                "previous_version_id": previous_version_id,
            },
            shared=True,
            created_by=uploaded_by,
        )
        self._session.add(record)
        self._session.flush()

        log.info(
            "Evidence uploaded: %s v%d (%s, %d bytes)",
            filename,
            version,
            content_hash[:12],
            size_bytes,
        )
        return doc

    def list_documents(
        self,
        control_id: str | None = None,
        framework: str | None = None,
        tag: str | None = None,
        include_expired: bool = False,
    ) -> list[EvidenceDocument]:
        """List evidence documents with optional filters."""
        from warlock.db.models import SavedQuery

        q = self._session.query(SavedQuery).filter(
            SavedQuery.query_type == self.QUERY_TYPE,
        )
        results = q.order_by(SavedQuery.created_at.desc()).all()

        docs: list[EvidenceDocument] = []
        seen_names: set[str] = set()

        for r in results:
            params = r.parameters or {}

            # Only show latest version per filename
            if r.name in seen_names:
                continue
            seen_names.add(r.name)

            # Apply filters
            if control_id and params.get("control_id") != control_id:
                continue
            if framework and params.get("framework") != framework:
                continue
            if tag and tag not in (params.get("tags") or []):
                continue

            expires_at = None
            if params.get("expires_at"):
                try:
                    expires_at = datetime.fromisoformat(params["expires_at"])
                except (ValueError, TypeError):
                    pass

            if not include_expired and expires_at:
                if ensure_aware(expires_at) < datetime.now(timezone.utc):
                    continue

            docs.append(
                EvidenceDocument(
                    id=r.id,
                    filename=r.name,
                    content_hash=params.get("content_hash", ""),
                    size_bytes=params.get("size_bytes", 0),
                    version=params.get("version", 1),
                    control_id=params.get("control_id"),
                    framework=params.get("framework"),
                    tags=params.get("tags", []),
                    uploaded_by=params.get("uploaded_by", ""),
                    uploaded_at=ensure_aware(r.created_at)
                    if r.created_at
                    else datetime.now(timezone.utc),
                    expires_at=expires_at,
                    description=r.description or "",
                    mime_type=params.get("mime_type", ""),
                    previous_version_id=params.get("previous_version_id"),
                )
            )
        return docs

    def get_versions(self, filename: str) -> list[EvidenceVersion]:
        """Get all versions of a document by filename."""
        from warlock.db.models import SavedQuery

        results = (
            self._session.query(SavedQuery)
            .filter(
                SavedQuery.query_type == self.QUERY_TYPE,
                SavedQuery.name == filename,
            )
            .order_by(SavedQuery.created_at.desc())
            .all()
        )

        versions: list[EvidenceVersion] = []
        for r in results:
            params = r.parameters or {}
            versions.append(
                EvidenceVersion(
                    version=params.get("version", 1),
                    content_hash=params.get("content_hash", ""),
                    size_bytes=params.get("size_bytes", 0),
                    uploaded_by=params.get("uploaded_by", ""),
                    uploaded_at=ensure_aware(r.created_at)
                    if r.created_at
                    else datetime.now(timezone.utc),
                    description=r.description or "",
                )
            )
        return versions

    def get_expiring(self, within_days: int = 30) -> list[EvidenceDocument]:
        """Get documents expiring within N days."""
        threshold = datetime.now(timezone.utc) + timedelta(days=within_days)
        docs = self.list_documents(include_expired=False)
        return [d for d in docs if d.expires_at and ensure_aware(d.expires_at) <= threshold]

    def get_stale(self, stale_days: int = 90) -> list[EvidenceDocument]:
        """Get documents not updated in N days (staleness detection)."""
        threshold = datetime.now(timezone.utc) - timedelta(days=stale_days)
        docs = self.list_documents(include_expired=True)
        return [d for d in docs if ensure_aware(d.uploaded_at) < threshold]

    @staticmethod
    def _guess_mime(filename: str) -> str:
        """Guess MIME type from filename extension."""
        ext = Path(filename).suffix.lower()
        return {
            ".pdf": "application/pdf",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".csv": "text/csv",
            ".json": "application/json",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".txt": "text/plain",
            ".md": "text/markdown",
            ".html": "text/html",
            ".xml": "application/xml",
            ".zip": "application/zip",
        }.get(ext, "application/octet-stream")
