"""Google Drive normalizer — transforms raw Google Drive API responses into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GoogleDriveNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Google Drive."""

    HANDLERS: dict[str, str] = {
        "google_drive_files": "_normalize_google_drive_files",
        "google_drive_shared_drives": "_normalize_google_drive_shared_drives",
        "google_drive_about": "_normalize_google_drive_about",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "google_drive" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "google_drive",
            "source_type": SourceType.FILE_STORAGE,
            "provider": "google_drive",
            "observed_at": raw.observed_at,
        }

    def _normalize_google_drive_files(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = [items]

        for item in items:
            item_id = str(item.get("id", item.get("name", item.get("key", ""))))
            item_name = str(item.get("name", item.get("label", item.get("title", item_id))))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title="Google Drive google drive files: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="google_drive_files",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_google_drive_shared_drives(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = [items]

        for item in items:
            item_id = str(item.get("id", item.get("name", item.get("key", ""))))
            item_name = str(item.get("name", item.get("label", item.get("title", item_id))))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title="Google Drive google drive shared drives: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="google_drive_shared_drives",
                    resource_name=item_name,
                    severity="medium",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_google_drive_about(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = [items]

        for item in items:
            item_id = str(item.get("id", item.get("name", item.get("key", ""))))
            item_name = str(item.get("name", item.get("label", item.get("title", item_id))))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title="Google Drive google drive about: " + item_name,
                    detail=item,
                    resource_id=item_id,
                    resource_type="google_drive_about",
                    resource_name=item_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(GoogleDriveNormalizer())
