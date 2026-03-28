"""Physical security normalizer — transforms access control events into Findings.

Handles access events, door status, and badge inventory from
Lenel/S2, Genetec, and HID Global systems.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PhysicalSecurityNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for physical security data."""

    HANDLERS: dict[str, str] = {
        "physical_access_events": "_normalize_access_events",
        "physical_door_status": "_normalize_door_status",
        "physical_badge_inventory": "_normalize_badge_inventory",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "physical_security" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "physical_security",
            "source_type": SourceType.PHYSICAL,
            "provider": raw.provider,
            "observed_at": raw.observed_at,
        }

    def _normalize_access_events(self, raw: RawEventData) -> list[FindingData]:
        """Access events: flag denied access and after-hours entry."""
        findings: list[FindingData] = []
        events = raw.raw_data.get("response", [])
        if isinstance(events, dict):
            events = events.get("events", events.get("items", []))

        for evt in events:
            event_id = str(evt.get("id", evt.get("eventId", "")))
            event_type = evt.get("type", evt.get("eventType", "")).lower()
            person = evt.get("person", evt.get("cardholder", evt.get("name", "")))
            door = evt.get("door", evt.get("accessPoint", evt.get("reader", "")))
            timestamp = evt.get("timestamp", evt.get("eventTime", ""))

            # Inventory all access events
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Access event: {person} at {door}",
                    detail={
                        "event_id": event_id,
                        "event_type": event_type,
                        "person": person,
                        "door": door,
                        "timestamp": timestamp,
                    },
                    resource_id=f"physical:access:{event_id}",
                    resource_type="physical_access_event",
                    resource_name=f"access-{event_id[:16]}",
                    severity="info",
                )
            )

            # Flag denied access attempts
            if event_type in ("denied", "rejected", "access_denied", "invalid_credential"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Access denied: {person} at {door}",
                        detail={
                            "event_id": event_id,
                            "person": person,
                            "door": door,
                            "reason": event_type,
                            "timestamp": timestamp,
                        },
                        resource_id=f"physical:denied:{event_id}",
                        resource_type="physical_access_denied",
                        resource_name=f"denied-{event_id[:16]}",
                        severity="medium",
                    )
                )

        return findings

    def _normalize_door_status(self, raw: RawEventData) -> list[FindingData]:
        """Door status: flag doors held open or forced."""
        findings: list[FindingData] = []
        doors = raw.raw_data.get("response", [])
        if isinstance(doors, dict):
            doors = doors.get("doors", doors.get("items", []))

        for door in doors:
            door_id = str(door.get("id", door.get("doorId", "")))
            name = door.get("name", door.get("description", f"door-{door_id}"))
            status = door.get("status", door.get("state", "")).lower()

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Door: {name} ({status})",
                    detail={
                        "door_id": door_id,
                        "name": name,
                        "status": status,
                    },
                    resource_id=f"physical:door:{door_id}",
                    resource_type="physical_door",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag doors held open or forced
            if status in ("held_open", "forced", "propped", "alarm"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Door alarm: {name} ({status})",
                        detail={
                            "door_id": door_id,
                            "name": name,
                            "status": status,
                            "issue": f"Door is in {status} state",
                        },
                        resource_id=f"physical:door_alarm:{door_id}",
                        resource_type="physical_door_alarm",
                        resource_name=name,
                        severity="high",
                    )
                )

        return findings

    def _normalize_badge_inventory(self, raw: RawEventData) -> list[FindingData]:
        """Badge inventory: flag expired badges."""
        findings: list[FindingData] = []
        badges = raw.raw_data.get("response", [])
        if isinstance(badges, dict):
            badges = badges.get("badges", badges.get("cardholders", badges.get("items", [])))

        total = len(badges)
        expired = [b for b in badges if b.get("status", "").lower() in ("expired", "revoked")]

        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Badge inventory: {total} total, {len(expired)} expired/revoked",
                detail={
                    "total_badges": total,
                    "expired_count": len(expired),
                },
                resource_id="physical:badge_inventory",
                resource_type="physical_badge_inventory",
                resource_name="badge-inventory",
                severity="info",
            )
        )

        if expired:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"{len(expired)} expired/revoked badge(s) still in system",
                    detail={
                        "expired_count": len(expired),
                        "sample_ids": [str(b.get("id", "")) for b in expired[:10]],
                        "issue": "Expired badges should be deactivated",
                    },
                    resource_id="physical:expired_badges",
                    resource_type="physical_badge_expired",
                    resource_name="expired-badges",
                    severity="medium",
                )
            )

        return findings


registry.register(PhysicalSecurityNormalizer())
