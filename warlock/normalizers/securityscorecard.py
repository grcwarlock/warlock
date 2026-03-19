"""SecurityScorecard normalizer — transforms raw SSC API responses into Findings.

Normalizes vendor portfolios, company scores, risk factors, and open issues
with third-party risk finding generation.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Grade-to-severity mapping for risk factors
_GRADE_SEVERITY: dict[str, str] = {
    "F": "critical",
    "D": "high",
    "C": "medium",
    "B": "low",
    "A": "info",
}


class SecurityScorecardNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "ssc_portfolios": "_normalize_portfolios",
        "ssc_companies": "_normalize_companies",
        "ssc_factors": "_normalize_factors",
        "ssc_issues": "_normalize_issues",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return (
            raw_event.source == "securityscorecard"
            and raw_event.event_type in self.HANDLERS
        )

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "securityscorecard",
            "source_type": SourceType.GRC,
            "provider": "securityscorecard",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Portfolios --

    def _normalize_portfolios(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        portfolios = raw.raw_data.get("response", [])

        for portfolio in portfolios:
            portfolio_id = portfolio.get("id", "")
            name = portfolio.get("name", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"SSC portfolio: {name}",
                detail={
                    "portfolio_id": portfolio_id,
                    "name": name,
                    "description": portfolio.get("description", ""),
                    "company_count": portfolio.get("total", portfolio.get("company_count", 0)),
                },
                resource_id=portfolio_id,
                resource_type="vendor_portfolio",
                resource_name=name,
                severity="info",
            ))

        return findings

    # -- Companies --

    def _normalize_companies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        companies = raw.raw_data.get("response", [])

        for company in companies:
            domain = company.get("domain", "")
            name = company.get("name", domain)
            score = company.get("score", company.get("overall_score", 0))
            portfolio_id = company.get("_portfolio_id", "")

            obs_type = "inventory"
            severity = "info"

            if isinstance(score, (int, float)):
                if score < 50:
                    obs_type = "alert"
                    severity = "critical"
                elif score < 70:
                    obs_type = "alert"
                    severity = "high"
                elif score <= 80:
                    obs_type = "alert"
                    severity = "medium"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"SSC vendor: {name} (score: {score})"
                      + (f" -- low score" if severity in ("critical", "high") else ""),
                detail={
                    "domain": domain,
                    "name": name,
                    "score": score,
                    "portfolio_id": portfolio_id,
                    "grade": company.get("grade", ""),
                    "industry": company.get("industry", ""),
                    "size": company.get("size", ""),
                    "last_score_change": company.get("last_score_change", 0),
                },
                resource_id=domain,
                resource_type="vendor_company",
                resource_name=name,
                severity=severity,
            ))

        return findings

    # -- Factors --

    def _normalize_factors(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        factor_entries = raw.raw_data.get("response", [])

        for entry in factor_entries:
            domain = entry.get("domain", "")
            factors = entry.get("factors", [])

            for factor in factors:
                factor_name = factor.get("name", "")
                grade = factor.get("grade", "").upper()
                score = factor.get("score", 0)

                severity = _GRADE_SEVERITY.get(grade, "info")
                obs_type = "misconfiguration" if grade in ("F", "D", "C") else "inventory"

                findings.append(FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"SSC factor: {factor_name} ({grade}) for {domain}",
                    detail={
                        "domain": domain,
                        "factor_name": factor_name,
                        "grade": grade,
                        "score": score,
                        "issue_count": factor.get("issue_count", 0),
                    },
                    resource_id=f"{domain}/{factor_name}",
                    resource_type="vendor_risk_factor",
                    resource_name=f"{factor_name} ({domain})",
                    severity=severity,
                ))

        return findings

    # -- Issues --

    def _normalize_issues(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        issues = raw.raw_data.get("response", [])

        for issue in issues:
            domain = issue.get("_domain", "")
            issue_type = issue.get("type", "")
            detail_url = issue.get("detail_url", "")
            severity_raw = (issue.get("severity", "medium")).lower()
            if severity_raw not in ("critical", "high", "medium", "low"):
                severity_raw = "medium"

            count = issue.get("count", 1)
            first_seen = issue.get("first_seen_time", "")
            last_seen = issue.get("last_seen_time", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="vulnerability",
                title=f"SSC issue: {issue_type} for {domain} ({severity_raw})",
                detail={
                    "domain": domain,
                    "type": issue_type,
                    "severity": severity_raw,
                    "count": count,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "detail_url": detail_url,
                    "issue": issue,
                },
                resource_id=f"{domain}/{issue_type}",
                resource_type="vendor_issue",
                resource_name=f"{issue_type} ({domain})",
                severity=severity_raw,
            ))

        return findings


# Register
registry.register(SecurityScorecardNormalizer())
