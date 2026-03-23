"""SecurityScorecard connector — Layer 1 implementation for third-party risk.

Collects vendor portfolios, company scores, risk factors, and open issues
from the SecurityScorecard REST API.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

SSC_BASE_URL = "https://api.securityscorecard.io"


class SecurityScorecardConnector(BaseConnector):
    """Collects third-party risk telemetry from SecurityScorecard REST APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append(
                "httpx not installed. Install with: pip install warlock[securityscorecard]"
            )
        if not self.get_secret("WLK_SSC_API_TOKEN"):
            errors.append("WLK_SSC_API_TOKEN env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("WLK_SSC_API_TOKEN")
            resp = httpx.get(
                f"{SSC_BASE_URL}/portfolios",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="securityscorecard",
            source_type=SourceType.GRC,
            provider="securityscorecard",
        )

        token = self.get_secret("WLK_SSC_API_TOKEN")
        headers = self._headers(token)

        client = httpx.Client(
            base_url=SSC_BASE_URL,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            # 1. Portfolios
            portfolios = []
            try:
                resp = client.get("/portfolios")
                resp.raise_for_status()
                body = resp.json()
                portfolios = body.get("entries", body) if isinstance(body, dict) else body
                if not isinstance(portfolios, list):
                    portfolios = [portfolios]
                result.events.append(
                    RawEventData(
                        source="securityscorecard",
                        source_type=SourceType.GRC,
                        provider="securityscorecard",
                        event_type="ssc_portfolios",
                        raw_data={
                            "endpoint": "/portfolios",
                            "response": portfolios,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("SSC portfolios failed: %s", e)
                result.errors.append(f"portfolios: {e}")

            # 2. Companies per portfolio
            all_companies = []
            for portfolio in portfolios:
                portfolio_id = portfolio.get("id", "")
                if not portfolio_id:
                    continue
                try:
                    resp = client.get(f"/portfolios/{portfolio_id}/companies")
                    resp.raise_for_status()
                    body = resp.json()
                    companies = body.get("entries", body) if isinstance(body, dict) else body
                    if not isinstance(companies, list):
                        companies = [companies]
                    for company in companies:
                        company["_portfolio_id"] = portfolio_id
                    all_companies.extend(companies)
                except Exception as e:
                    log.debug("SSC portfolio %s companies failed: %s", portfolio_id, e)
                    result.errors.append(f"portfolio_{portfolio_id}_companies: {e}")

            if all_companies:
                result.events.append(
                    RawEventData(
                        source="securityscorecard",
                        source_type=SourceType.GRC,
                        provider="securityscorecard",
                        event_type="ssc_companies",
                        raw_data={
                            "endpoint": "/portfolios/{id}/companies",
                            "response": all_companies,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )

            # 3. Risk factors per company
            all_factors = []
            domains = []
            for company in all_companies:
                domain = company.get("domain", "")
                if domain:
                    domains.append(domain)

            for domain in domains[:50]:  # cap to avoid rate limits
                try:
                    resp = client.get(f"/companies/{domain}/factors")
                    resp.raise_for_status()
                    body = resp.json()
                    factors = body.get("entries", body) if isinstance(body, dict) else body
                    all_factors.append(
                        {
                            "domain": domain,
                            "factors": factors if isinstance(factors, list) else [factors],
                        }
                    )
                except Exception as e:
                    log.debug("SSC factors for %s failed: %s", domain, e)

            if all_factors:
                result.events.append(
                    RawEventData(
                        source="securityscorecard",
                        source_type=SourceType.GRC,
                        provider="securityscorecard",
                        event_type="ssc_factors",
                        raw_data={
                            "endpoint": "/companies/{domain}/factors",
                            "response": all_factors,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )

            # 4. High/critical issues per company
            all_issues = []
            for domain in domains[:50]:
                try:
                    resp = client.get(
                        f"/companies/{domain}/issues",
                        params={"severity": "high,critical"},
                    )
                    resp.raise_for_status()
                    body = resp.json()
                    issues = body.get("entries", body) if isinstance(body, dict) else body
                    if not isinstance(issues, list):
                        issues = [issues]
                    for issue in issues:
                        issue["_domain"] = domain
                    all_issues.extend(issues)
                except Exception as e:
                    log.debug("SSC issues for %s failed: %s", domain, e)

            if all_issues:
                result.events.append(
                    RawEventData(
                        source="securityscorecard",
                        source_type=SourceType.GRC,
                        provider="securityscorecard",
                        event_type="ssc_issues",
                        raw_data={
                            "endpoint": "/companies/{domain}/issues",
                            "response": all_issues,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )

        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Token {token}",
            "Accept": "application/json",
        }


# Register
registry.register("securityscorecard", SecurityScorecardConnector)
