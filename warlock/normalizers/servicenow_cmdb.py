"""ServiceNow CMDB normalizer — transforms raw ServiceNow Table API responses into Findings.

Normalizes configuration items, CI relationships, and CI classes as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# ServiceNow operational_status values: 1=Operational, 2=Non-Operational, 3=Repair in Progress,
# 4=DR Standby, 5=Ready, 6=Retired, 7=Pipeline, 8=Catalog
_OPERATIONAL_STATUS_MAP: dict[str, str] = {
    "1": "operational",
    "2": "non_operational",
    "3": "repair_in_progress",
    "6": "retired",
}


class ServiceNowCMDBNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "servicenow_cmdb_cis": "_normalize_cis",
        "servicenow_cmdb_relationships": "_normalize_relationships",
        "servicenow_cmdb_classes": "_normalize_classes",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "servicenow_cmdb" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all ServiceNow CMDB findings."""
        return {
            "raw_event_id": raw.id,
            "source": "servicenow_cmdb",
            "source_type": SourceType.ITSM,
            "provider": "servicenow_cmdb",
            "account_id": raw.raw_data.get("base_url", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _sn_val(self, field: object) -> str:
        """Extract value from ServiceNow reference fields (which may be dicts with 'value' key)."""
        if isinstance(field, dict):
            return str(field.get("value", field.get("display_value", "")))
        return str(field) if field is not None else ""

    # -- Configuration Items --

    def _normalize_cis(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for ci in items:
            sys_id = self._sn_val(ci.get("sys_id", ""))
            name = self._sn_val(ci.get("name", "unknown"))
            ci_class = self._sn_val(ci.get("sys_class_name", ""))
            op_status = self._sn_val(ci.get("operational_status", ""))
            install_status = self._sn_val(ci.get("install_status", ""))
            ip_address = self._sn_val(ci.get("ip_address", ""))

            op_label = _OPERATIONAL_STATUS_MAP.get(op_status, op_status)
            severity = "info"
            obs_type = "inventory"
            if op_label in ("non_operational", "retired"):
                severity = "low"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"ServiceNow CI: {name}",
                    detail={
                        "sys_id": sys_id,
                        "name": name,
                        "sys_class_name": ci_class,
                        "operational_status": op_label,
                        "install_status": install_status,
                        "ip_address": ip_address,
                        "fqdn": self._sn_val(ci.get("fqdn", "")),
                        "manufacturer": self._sn_val(ci.get("manufacturer", "")),
                        "serial_number": self._sn_val(ci.get("serial_number", "")),
                    },
                    resource_id=sys_id,
                    resource_type="servicenow_ci",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- CI Relationships --

    def _normalize_relationships(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for rel in items:
            sys_id = self._sn_val(rel.get("sys_id", ""))
            parent = self._sn_val(rel.get("parent", ""))
            child = self._sn_val(rel.get("child", ""))
            rel_type = self._sn_val(rel.get("type", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"ServiceNow CI relationship: {parent} → {child}",
                    detail={
                        "sys_id": sys_id,
                        "parent": parent,
                        "child": child,
                        "type": rel_type,
                    },
                    resource_id=sys_id,
                    resource_type="servicenow_ci_relationship",
                    resource_name=f"{parent} -> {child}",
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    # -- CI Classes --

    def _normalize_classes(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for ci_class in items:
            sys_id = self._sn_val(ci_class.get("sys_id", ""))
            name = self._sn_val(ci_class.get("name", "unknown"))
            label = self._sn_val(ci_class.get("label", name))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"ServiceNow CI class: {label}",
                    detail={
                        "sys_id": sys_id,
                        "name": name,
                        "label": label,
                    },
                    resource_id=sys_id,
                    resource_type="servicenow_ci_class",
                    resource_name=label,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ServiceNowCMDBNormalizer())
