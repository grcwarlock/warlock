"""Generic / fallback normalizer — best-effort normalization for manual
uploads and webhook payloads that lack a source-specific normalizer.

Handles ``source="manual"`` or ``source="webhook"`` events, or any event
that no other normalizer claims.  It probes the raw data for common field
names and constructs one or more findings.  When nothing recognisable is
found it produces a single finding with ``observation_type="unknown"``.
"""

from __future__ import annotations

import logging
from typing import Any

from warlock.connectors.base import RawEventData
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

log = logging.getLogger(__name__)

# Severity aliases we recognise in raw payloads.
_SEVERITY_ALIASES: dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "none": "info",
}

# Keys we scan for a list of "items" to fan-out into individual findings.
_LIST_KEYS = (
    "findings", "alerts", "vulnerabilities", "results",
    "detections", "events", "issues", "items",
)

# Keys we probe for a human-readable title.
_TITLE_KEYS = ("title", "name", "summary", "message", "subject", "description")

# Keys we probe for severity.
_SEVERITY_KEYS = ("severity", "priority", "risk", "risk_level", "criticality", "level")

# Keys we probe for a resource identifier.
_RESOURCE_ID_KEYS = ("resource_id", "resourceId", "resource", "asset_id", "assetId", "host", "hostname", "target")
_RESOURCE_TYPE_KEYS = ("resource_type", "resourceType", "asset_type", "assetType", "type")
_RESOURCE_NAME_KEYS = ("resource_name", "resourceName", "name", "hostname", "host")


def _extract(data: dict[str, Any], keys: tuple[str, ...], default: str = "") -> str:
    """Return the first truthy string value found for any of *keys*."""
    for key in keys:
        val = data.get(key)
        if val and isinstance(val, str):
            return val
    return default


def _extract_severity(data: dict[str, Any]) -> str:
    raw = _extract(data, _SEVERITY_KEYS).lower()
    return _SEVERITY_ALIASES.get(raw, "info")


def _observation_type_hint(data: dict[str, Any]) -> str:
    """Guess the observation type from the payload keys."""
    text = " ".join(str(k) for k in data.keys()).lower()
    if "vulnerability" in text or "cve" in text:
        return "vulnerability"
    if "alert" in text or "detection" in text:
        return "alert"
    if "misconfiguration" in text or "config" in text:
        return "misconfiguration"
    if "policy" in text or "compliance" in text:
        return "policy_violation"
    if "access" in text or "identity" in text or "iam" in text:
        return "access_anomaly"
    return "unknown"


def _finding_from_item(
    raw: RawEventData,
    item: dict[str, Any],
) -> FindingData:
    """Build a single FindingData from one item dict."""
    title = _extract(item, _TITLE_KEYS) or f"{raw.provider} finding"
    severity = _extract_severity(item)
    obs_type = _observation_type_hint(item)
    resource_id = _extract(item, _RESOURCE_ID_KEYS)
    resource_type = _extract(item, _RESOURCE_TYPE_KEYS)
    resource_name = _extract(item, _RESOURCE_NAME_KEYS)

    return FindingData(
        raw_event_id=raw.id,
        observation_type=obs_type,
        title=title,
        detail=item,
        resource_id=resource_id,
        resource_type=resource_type,
        resource_name=resource_name,
        source=raw.source,
        source_type=raw.source_type,
        provider=raw.provider,
        severity=severity,
        confidence=0.5,
        observed_at=raw.observed_at,
    )


class GenericNormalizer(BaseNormalizer):
    """Fallback normalizer for webhook / manual events without a
    dedicated normalizer.

    Priority: registered **last** so source-specific normalizers get
    first crack.
    """

    def can_handle(self, raw_event: RawEventData) -> bool:
        # Accept anything — this is the fallback.  Because it is
        # registered last in the normalizer list, source-specific
        # normalizers that return True from ``can_handle`` will
        # always take precedence.
        return True

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        data = raw_event.raw_data

        # Try to fan-out over a list of sub-items.
        for key in _LIST_KEYS:
            items = data.get(key)
            if isinstance(items, list) and items:
                findings: list[FindingData] = []
                for item in items:
                    if isinstance(item, dict):
                        findings.append(_finding_from_item(raw_event, item))
                if findings:
                    log.debug(
                        "GenericNormalizer: fan-out on key=%s produced %d finding(s)",
                        key, len(findings),
                    )
                    return findings

        # No recognised list key — treat the whole payload as a single item.
        return [_finding_from_item(raw_event, data)]


# Register — append so it sorts after all source-specific normalizers.
registry.register(GenericNormalizer())
