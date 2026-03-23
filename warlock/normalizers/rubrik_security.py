"""Rubrik Security Cloud normalizer — transforms raw Rubrik Security API responses into Findings.

Normalizes data classifications and sensitive files as inventory,
anomalies as DLP alert findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
}


class RubrikSecurityNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Rubrik Security Cloud findings."""

    HANDLERS: dict[str, str] = {
        "rubrik_security_data_classification": "_normalize_data_classification",
        "rubrik_security_anomalies": "_normalize_anomalies",
        "rubrik_security_sensitive_files": "_normalize_sensitive_files",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "rubrik_security" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "rubrik_security",
            "source_type": SourceType.DLP,
            "provider": "rubrik_security",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_data_classification(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("results", []))
        )

        for item in items:
            item_id = str(item.get("id", ""))
            name = item.get("name", item.get("objectName", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Rubrik Security classification: {name}",
                    detail={
                        "object_id": item_id,
                        "name": name,
                        "classification": item.get("classification", ""),
                        "data_type": item.get("type", ""),
                        "match_count": item.get("matchCount", 0),
                    },
                    resource_id=item_id,
                    resource_type="rubrik_security_classification",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_anomalies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("anomalies", []))
        )

        for anomaly in items:
            anomaly_id = str(anomaly.get("id", ""))
            name = anomaly.get("name", anomaly.get("objectName", "Anomaly"))
            severity_raw = str(anomaly.get("severity", "LOW")).upper()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Rubrik Security anomaly: {name}",
                    detail={
                        "anomaly_id": anomaly_id,
                        "name": name,
                        "severity": severity_raw,
                        "anomaly_type": anomaly.get("anomalyType", ""),
                        "affected_files": anomaly.get("affectedFiles", 0),
                        "detected_at": anomaly.get("detectedAt", ""),
                        "cluster": anomaly.get("clusterName", ""),
                    },
                    resource_id=anomaly_id,
                    resource_type="rubrik_security_anomaly",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sensitive_files(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("sensitiveFiles", []))
        )

        for sfile in items:
            file_id = str(sfile.get("id", ""))
            name = sfile.get("fileName", sfile.get("name", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Rubrik Security sensitive file: {name}",
                    detail={
                        "file_id": file_id,
                        "name": name,
                        "path": sfile.get("filePath", ""),
                        "sensitivity": sfile.get("sensitivityLabel", ""),
                        "hit_count": sfile.get("hitCount", 0),
                        "data_types": sfile.get("dataTypes", []),
                        "last_modified": sfile.get("lastModifiedTime", ""),
                    },
                    resource_id=file_id,
                    resource_type="rubrik_security_sensitive_file",
                    resource_name=name,
                    severity="high",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(RubrikSecurityNormalizer())
