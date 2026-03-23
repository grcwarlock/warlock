"""Zoom normalizer — transforms raw Zoom API responses into Findings.

Normalizes user accounts (as inventory), meetings (as inventory), and daily
usage reports (as inventory with engagement metrics).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class ZoomNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "zoom_users": "_normalize_users",
        "zoom_meetings": "_normalize_meetings",
        "zoom_daily_report": "_normalize_daily_report",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "zoom" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "zoom",
            "source_type": SourceType.COLLABORATION,
            "provider": "zoom",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for user in items:
            user_id = str(user.get("id", ""))
            email = user.get("email", "unknown")
            first_name = user.get("first_name", "")
            last_name = user.get("last_name", "")
            status = user.get("status", "unknown")
            user_type = user.get("type", 1)  # 1=Basic, 2=Licensed, 3=On-prem

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Zoom user: {email}",
                    detail={
                        "user_id": user_id,
                        "email": email,
                        "first_name": first_name,
                        "last_name": last_name,
                        "status": status,
                        "user_type": user_type,
                        "created_at": user.get("created_at", ""),
                        "last_login_time": user.get("last_login_time", ""),
                        "pmi": user.get("pmi", ""),
                    },
                    resource_id=user_id,
                    resource_type="zoom_user",
                    resource_name=email,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_meetings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for meeting in items:
            meeting_id = str(meeting.get("id", ""))
            topic = meeting.get("topic", "unknown")
            host_id = meeting.get("host_id", "")
            meeting_type = meeting.get("type", 2)
            start_time = meeting.get("start_time", "")
            duration = meeting.get("duration", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Zoom meeting: {topic}",
                    detail={
                        "meeting_id": meeting_id,
                        "topic": topic,
                        "host_id": host_id,
                        "type": meeting_type,
                        "start_time": start_time,
                        "duration_minutes": duration,
                        "password_protected": bool(meeting.get("password", "")),
                        "join_url": meeting.get("join_url", ""),
                    },
                    resource_id=meeting_id,
                    resource_type="zoom_meeting",
                    resource_name=topic,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_daily_report(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for day in items:
            date = str(day.get("date", ""))
            new_users = day.get("new_users", 0)
            meetings = day.get("meetings", 0)
            participants = day.get("participants", 0)
            meeting_minutes = day.get("meeting_minutes", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Zoom daily report: {date}",
                    detail={
                        "date": date,
                        "new_users": new_users,
                        "meetings": meetings,
                        "participants": participants,
                        "meeting_minutes": meeting_minutes,
                    },
                    resource_id=date,
                    resource_type="zoom_daily_report",
                    resource_name=date,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(ZoomNormalizer())
