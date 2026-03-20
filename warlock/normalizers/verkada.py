"""Verkada normalizer — transforms raw Verkada API responses into Findings.

Normalizes access events (after-hours detection), doors (unlocked detection),
and card holders into inventory, misconfiguration, and access anomaly findings.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Business hours: 7 AM to 7 PM (configurable per-org in practice)
BUSINESS_HOURS_START = 7
BUSINESS_HOURS_END = 19


class VerkadaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "verkada_access_events": "_normalize_access_events",
        "verkada_doors": "_normalize_doors",
        "verkada_users": "_normalize_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "verkada" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Verkada findings."""
        return {
            "raw_event_id": raw.id,
            "source": "verkada",
            "source_type": SourceType.PHYSICAL,
            "provider": "verkada",
            "observed_at": raw.observed_at,
        }

    # -- Access Events --

    def _normalize_access_events(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per access event; anomaly for after-hours access."""
        findings = []
        events = raw.raw_data.get("response", [])
        if isinstance(events, dict):
            events = events.get("access_events", events.get("results", []))

        for event in events:
            event_id = str(event.get("event_id", event.get("id", "")))
            user_name = event.get("user_name", event.get("actor_name", "unknown"))
            door_name = event.get("door_name", event.get("door", {}).get("name", "unknown"))
            event_time_str = event.get("event_time", event.get("timestamp", ""))
            event_type = event.get("event_type", "")

            # Inventory finding
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Access event: {user_name} at {door_name}",
                    detail={
                        "event_id": event_id,
                        "user_name": user_name,
                        "door_name": door_name,
                        "event_time": event_time_str,
                        "event_type": event_type,
                    },
                    resource_id=f"verkada:access_event:{event_id}",
                    resource_type="physical_access_event",
                    resource_name=f"{user_name}@{door_name}",
                    severity="info",
                )
            )

            # After-hours access detection
            event_dt = self._parse_dt(event_time_str)
            if event_dt and self._is_after_hours(event_dt):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="access_anomaly",
                        title=f"After-hours access: {user_name} at {door_name} ({event_dt.strftime('%H:%M')})",
                        detail={
                            "event_id": event_id,
                            "user_name": user_name,
                            "door_name": door_name,
                            "event_time": event_time_str,
                            "hour": event_dt.hour,
                            "issue": "after_hours_access",
                        },
                        resource_id=f"verkada:access_event:{event_id}",
                        resource_type="physical_access_event",
                        resource_name=f"{user_name}@{door_name}",
                        severity="medium",
                    )
                )

        return findings

    # -- Doors --

    def _normalize_doors(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per door; misconfiguration for unlocked doors."""
        findings = []
        data = raw.raw_data.get("response", {})
        doors = data if isinstance(data, list) else data.get("doors", data.get("results", []))

        for door in doors:
            door_id = str(door.get("door_id", door.get("id", "")))
            door_name = door.get("name", "unknown")
            lock_status = door.get("lock_status", door.get("state", ""))
            site = door.get("site", "")

            # Inventory finding
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Door: {door_name}",
                    detail={
                        "door_id": door_id,
                        "door_name": door_name,
                        "lock_status": lock_status,
                        "site": site,
                    },
                    resource_id=f"verkada:door:{door_id}",
                    resource_type="physical_door",
                    resource_name=door_name,
                    severity="info",
                )
            )

            # Unlocked door detection
            if lock_status.lower() in ("unlocked", "open", "forced_open"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Unlocked door: {door_name} (status: {lock_status})",
                        detail={
                            "door_id": door_id,
                            "door_name": door_name,
                            "lock_status": lock_status,
                            "site": site,
                            "issue": "door_unlocked",
                        },
                        resource_id=f"verkada:door:{door_id}",
                        resource_type="physical_door",
                        resource_name=door_name,
                        severity="high",
                    )
                )

        return findings

    # -- Users / Card Holders --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        """One inventory finding per card holder."""
        findings = []
        data = raw.raw_data.get("response", {})
        users = (
            data if isinstance(data, list) else data.get("card_holders", data.get("results", []))
        )

        for user in users:
            user_id = str(user.get("user_id", user.get("id", "")))
            name = user.get("full_name", user.get("name", "unknown"))
            email = user.get("email", "")
            department = user.get("department", "")
            active = user.get("active", True)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Card holder: {name}",
                    detail={
                        "user_id": user_id,
                        "name": name,
                        "email": email,
                        "department": department,
                        "active": active,
                    },
                    resource_id=f"verkada:user:{user_id}",
                    resource_type="physical_access_user",
                    resource_name=name,
                    severity="info",
                )
            )

        return findings

    @staticmethod
    def _is_after_hours(dt: datetime) -> bool:
        """Check if a datetime falls outside business hours."""
        return dt.hour < BUSINESS_HOURS_START or dt.hour >= BUSINESS_HOURS_END

    @staticmethod
    def _parse_dt(dt_str: str) -> datetime | None:
        """Parse an ISO 8601 or epoch timestamp."""
        if not dt_str:
            return None
        try:
            # Try epoch seconds first (Verkada often uses epoch)
            if isinstance(dt_str, (int, float)):
                return datetime.fromtimestamp(float(dt_str), tz=timezone.utc)
            if dt_str.isdigit() or (dt_str.replace(".", "", 1).isdigit()):
                return datetime.fromtimestamp(float(dt_str), tz=timezone.utc)
            # ISO 8601
            cleaned = str(dt_str).replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except (ValueError, TypeError, OSError):
            return None


# Register
registry.register(VerkadaNormalizer())
