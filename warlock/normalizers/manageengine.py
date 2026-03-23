"""ManageEngine normalizer — transforms raw ManageEngine API responses into Findings.

Normalizes requests, assets, and changes as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ManageEngineNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for ManageEngine ServiceDesk Plus."""

    HANDLERS: dict[str, str] = {
        "manageengine_requests": "_normalize_requests",
        "manageengine_assets": "_normalize_assets",
        "manageengine_changes": "_normalize_changes",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "manageengine" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "manageengine",
            "source_type": SourceType.ITSM,
            "provider": "manageengine",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_requests(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for request in items:
            request_id = str(request.get("id", ""))
            subject = request.get("subject", "unknown")
            status = (request.get("status") or {}).get("name", "unknown")
            priority = (request.get("priority") or {}).get("name", "low")
            requester = (request.get("requester") or {}).get("name", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"ManageEngine request: {subject}",
                    detail={
                        "request_id": request_id,
                        "subject": subject,
                        "status": status,
                        "priority": priority,
                        "requester": requester,
                        "created_time": request.get("created_time", {}).get("value", "")
                        if isinstance(request.get("created_time"), dict)
                        else "",
                    },
                    resource_id=request_id,
                    resource_type="manageengine_request",
                    resource_name=subject,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for asset in items:
            asset_id = str(asset.get("id", ""))
            name = asset.get("name", "unknown")
            asset_type = (asset.get("asset_type") or {}).get("name", "")
            state = (asset.get("state") or {}).get("name", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"ManageEngine asset: {name}",
                    detail={
                        "asset_id": asset_id,
                        "name": name,
                        "asset_type": asset_type,
                        "state": state,
                        "department": (asset.get("department") or {}).get("name", "")
                        if isinstance(asset.get("department"), dict)
                        else "",
                        "location": (asset.get("location") or {}).get("name", "")
                        if isinstance(asset.get("location"), dict)
                        else "",
                    },
                    resource_id=asset_id,
                    resource_type="manageengine_asset",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_changes(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for change in items:
            change_id = str(change.get("id", ""))
            title = change.get("title", "unknown")
            status = (change.get("status") or {}).get("name", "unknown")
            change_type = (change.get("change_type") or {}).get("name", "")
            scheduled_start = change.get("scheduled_start_time", {}).get("value", "") \
                if isinstance(change.get("scheduled_start_time"), dict) else ""

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"ManageEngine change: {title}",
                    detail={
                        "change_id": change_id,
                        "title": title,
                        "status": status,
                        "change_type": change_type,
                        "scheduled_start": scheduled_start,
                        "requester": (change.get("requester") or {}).get("name", "")
                        if isinstance(change.get("requester"), dict)
                        else "",
                    },
                    resource_id=change_id,
                    resource_type="manageengine_change",
                    resource_name=title,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ManageEngineNormalizer())
