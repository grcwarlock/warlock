"""Confluence normalizer — transforms raw Confluence API responses into Findings.

Normalizes pages (stale page detection, missing author), and page versions
into inventory and misconfiguration findings.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ConfluenceNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "confluence_pages": "_normalize_pages",
        "confluence_page_versions": "_normalize_page_versions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "confluence" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Confluence findings."""
        return {
            "raw_event_id": raw.id,
            "source": "confluence",
            "source_type": SourceType.GRC,
            "provider": "confluence",
            "observed_at": raw.observed_at,
        }

    # -- Pages --

    def _normalize_pages(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per page, plus misconfigurations for stale/authorless pages."""
        findings = []
        pages = raw.raw_data.get("pages", [])
        space_key = raw.raw_data.get("space_key", "")
        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=365)

        for page in pages:
            page_id = str(page.get("id", ""))
            title = page.get("title", "Untitled")
            status = page.get("status", "")
            author_id = page.get("authorId", page.get("ownerId", ""))

            # Parse last modified date
            version = page.get("version", {})
            modified_str = version.get("createdAt", page.get("createdAt", ""))
            last_modified = self._parse_dt(modified_str) if modified_str else None

            # Inventory finding for every page
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Confluence page: {title}",
                    detail={
                        "page_id": page_id,
                        "title": title,
                        "space_key": space_key,
                        "status": status,
                        "author_id": author_id,
                        "last_modified": modified_str,
                    },
                    resource_id=f"confluence:{space_key}:{page_id}",
                    resource_type="grc_document",
                    resource_name=title,
                    severity="info",
                )
            )

            # Stale page: not updated in 365 days
            if last_modified and last_modified < stale_threshold:
                days_stale = (now - last_modified).days
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Stale Confluence page: {title} (not updated in {days_stale} days)",
                        detail={
                            "page_id": page_id,
                            "title": title,
                            "space_key": space_key,
                            "last_modified": modified_str,
                            "days_stale": days_stale,
                        },
                        resource_id=f"confluence:{space_key}:{page_id}",
                        resource_type="grc_document",
                        resource_name=title,
                        severity="medium",
                    )
                )

            # Missing author
            if not author_id:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Confluence page without author: {title}",
                        detail={
                            "page_id": page_id,
                            "title": title,
                            "space_key": space_key,
                            "issue": "no_author",
                        },
                        resource_id=f"confluence:{space_key}:{page_id}",
                        resource_type="grc_document",
                        resource_name=title,
                        severity="low",
                    )
                )

        return findings

    # -- Page Versions --

    def _normalize_page_versions(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per page version."""
        findings = []
        versions = raw.raw_data.get("versions", [])
        page_id = raw.raw_data.get("page_id", "")
        page_title = raw.raw_data.get("page_title", "")
        space_key = raw.raw_data.get("space_key", "")

        for ver in versions:
            version_number = ver.get("number", ver.get("versionNumber", ""))
            created_at = ver.get("createdAt", "")
            author_id = ver.get("authorId", "")
            message = ver.get("message", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Confluence page version: {page_title} v{version_number}",
                    detail={
                        "page_id": page_id,
                        "page_title": page_title,
                        "space_key": space_key,
                        "version_number": version_number,
                        "created_at": created_at,
                        "author_id": author_id,
                        "message": message,
                    },
                    resource_id=f"confluence:{space_key}:{page_id}:v{version_number}",
                    resource_type="grc_document_version",
                    resource_name=f"{page_title} v{version_number}",
                    severity="info",
                )
            )

        return findings

    @staticmethod
    def _parse_dt(dt_str: str) -> datetime | None:
        """Parse an ISO 8601 datetime string."""
        try:
            # Handle Confluence ISO format (may have Z or +00:00)
            cleaned = dt_str.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except (ValueError, TypeError):
            return None


# Register
registry.register(ConfluenceNormalizer())
