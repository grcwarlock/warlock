"""SAP SuccessFactors normalizer — transforms raw SAP SF OData responses into Findings.

Normalizes user records and employment records as inventory.
Terminated employees with lingering records are flagged as access_anomaly.
Background certificate records are normalized as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SAPSuccessFactorsNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "sap_sf_users": "_normalize_users",
        "sap_sf_employment": "_normalize_employment",
        "sap_sf_certificates": "_normalize_certificates",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sap_successfactors" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "sap_successfactors",
            "source_type": SourceType.HRIS,
            "provider": "sap_successfactors",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for user in items:
            user_id = str(user.get("userId", ""))
            username = user.get("username", user.get("loginMethod", "unknown"))
            first_name = user.get("firstName", "")
            last_name = user.get("lastName", "")
            full_name = f"{first_name} {last_name}".strip() or username
            status = user.get("status", "active").lower()
            email = user.get("email", "")

            is_inactive = status in ("inactive", "terminated", "deleted")
            obs_type = "access_anomaly" if is_inactive else "inventory"
            severity = "medium" if is_inactive else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"SAP SF user: {full_name}",
                    detail={
                        "user_id": user_id,
                        "username": username,
                        "full_name": full_name,
                        "email": email,
                        "status": status,
                        "is_inactive": is_inactive,
                        "department": user.get("department", ""),
                        "title": user.get("title", ""),
                        "hire_date": user.get("hireDate", ""),
                    },
                    resource_id=user_id,
                    resource_type="sap_sf_user",
                    resource_name=full_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_employment(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for emp in items:
            user_id = str(emp.get("userId", ""))
            start_date = emp.get("startDate", "")
            end_date = emp.get("endDate", "")
            active = emp.get("isContingentWorker", False)
            employment_type = emp.get("employmentType", "")

            # If endDate is present and non-null, treat as potentially terminated
            has_end_date = bool(end_date and end_date not in ("null", ""))
            obs_type = "access_anomaly" if has_end_date else "inventory"
            severity = "medium" if has_end_date else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"SAP SF employment: user {user_id}",
                    detail={
                        "user_id": user_id,
                        "start_date": start_date,
                        "end_date": end_date,
                        "employment_type": employment_type,
                        "is_contingent_worker": active,
                        "job_code": emp.get("jobCode", ""),
                        "company": emp.get("company", ""),
                        "has_end_date": has_end_date,
                    },
                    resource_id=user_id,
                    resource_type="sap_sf_employment",
                    resource_name=f"employment/{user_id}",
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_certificates(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for cert in items:
            cert_id = str(cert.get("backgroundElementId", cert.get("id", "")))
            user_id = str(cert.get("userId", ""))
            name = cert.get("name", "unknown")
            authority = cert.get("issuedBy", cert.get("authority", ""))
            issued_date = cert.get("issueDate", "")
            expiry_date = cert.get("expirationDate", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"SAP SF certificate: {name}",
                    detail={
                        "cert_id": cert_id,
                        "user_id": user_id,
                        "name": name,
                        "authority": authority,
                        "issued_date": issued_date,
                        "expiry_date": expiry_date,
                        "description": cert.get("notes", ""),
                    },
                    resource_id=cert_id,
                    resource_type="sap_sf_certificate",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SAPSuccessFactorsNormalizer())
