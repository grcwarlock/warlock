"""Workday HCM connector — Layer 1 implementation for HRIS.

Collects workers, background checks, employment agreements, disciplinary actions,
and job changes. Uses Workday HCM REST API via httpx with OAuth 2.0 client credentials.
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


class WorkdayConnector(BaseConnector):
    """Collects compliance telemetry from Workday HCM REST APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[workday]")
        if not self.get_secret("WLK_WORKDAY_CLIENT_ID"):
            errors.append("WLK_WORKDAY_CLIENT_ID env var is not set")
        if not self.get_secret("WLK_WORKDAY_CLIENT_SECRET"):
            errors.append("WLK_WORKDAY_CLIENT_SECRET env var is not set")
        if not self.get_secret("WLK_WORKDAY_TENANT"):
            errors.append("WLK_WORKDAY_TENANT env var is not set")
        if not self.config.settings.get("tenant"):
            errors.append("'tenant' must be set in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            tenant = self.config.settings["tenant"]
            api_version = self.config.settings.get("api_version", "v1")
            base_url = f"https://wd2-impl-services1.workday.com/ccx/api/{api_version}/{tenant}"
            token = self._get_oauth_token()
            resp = httpx.get(
                f"{base_url}/workers",
                headers=self._headers(token),
                params={"limit": "1"},
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="workday",
            source_type=SourceType.HRIS,
            provider="workday",
        )

        tenant = self.config.settings["tenant"]
        api_version = self.config.settings.get("api_version", "v1")
        base_url = f"https://wd2-impl-services1.workday.com/ccx/api/{api_version}/{tenant}"
        token = self._get_oauth_token()
        headers = self._headers(token)

        client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            # 1. Workers — paginated worker list
            try:
                workers = self._paginate(client, "/workers", {"limit": "100"})
                result.events.append(RawEventData(
                    source="workday",
                    source_type=SourceType.HRIS,
                    provider="workday",
                    event_type="workday_employees",
                    raw_data={
                        "endpoint": "/workers",
                        "tenant": tenant,
                        "response": workers,
                    },
                    observed_at=datetime.now(timezone.utc),
                ))
            except Exception as e:
                log.debug("Workday /workers failed: %s", e)
                result.errors.append(f"/workers: {e}")

            # 2. Background checks — enrichment per worker
            try:
                bg_checks = []
                workers_data = []
                for ev in result.events:
                    if ev.event_type == "workday_employees":
                        workers_data = ev.raw_data.get("response", [])
                        break
                for worker in workers_data[:500]:  # cap to avoid rate limits
                    wid = worker.get("id", "")
                    if not wid:
                        continue
                    try:
                        resp = client.get(f"/workers/{wid}")
                        resp.raise_for_status()
                        detail = resp.json()
                        bg_status = detail.get("backgroundCheck", {})
                        if bg_status:
                            bg_checks.append({
                                "worker_id": wid,
                                "worker_name": worker.get("descriptor", ""),
                                "background_check": bg_status,
                            })
                    except Exception:
                        pass
                if bg_checks:
                    result.events.append(RawEventData(
                        source="workday",
                        source_type=SourceType.HRIS,
                        provider="workday",
                        event_type="workday_background_checks",
                        raw_data={
                            "endpoint": "/workers/{id}",
                            "tenant": tenant,
                            "response": bg_checks,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
            except Exception as e:
                log.debug("Workday background checks failed: %s", e)
                result.errors.append(f"background_checks: {e}")

            # 3. Employment agreements — custom report
            try:
                agreements = self._fetch_custom_report(client, "employment_agreements")
                if agreements:
                    result.events.append(RawEventData(
                        source="workday",
                        source_type=SourceType.HRIS,
                        provider="workday",
                        event_type="workday_agreements",
                        raw_data={
                            "endpoint": "/custom_report/employment_agreements",
                            "tenant": tenant,
                            "response": agreements,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
            except Exception as e:
                log.debug("Workday agreements report failed: %s", e)
                result.errors.append(f"agreements: {e}")

            # 4. Disciplinary actions — custom report
            try:
                disciplinary = self._fetch_custom_report(client, "disciplinary_actions")
                if disciplinary:
                    result.events.append(RawEventData(
                        source="workday",
                        source_type=SourceType.HRIS,
                        provider="workday",
                        event_type="workday_disciplinary",
                        raw_data={
                            "endpoint": "/custom_report/disciplinary_actions",
                            "tenant": tenant,
                            "response": disciplinary,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
            except Exception as e:
                log.debug("Workday disciplinary report failed: %s", e)
                result.errors.append(f"disciplinary: {e}")

            # 5. Job changes — workers with job change filter
            try:
                job_changes = self._paginate(
                    client, "/workers", {"limit": "100", "search": "jobChange"}
                )
                if job_changes:
                    result.events.append(RawEventData(
                        source="workday",
                        source_type=SourceType.HRIS,
                        provider="workday",
                        event_type="workday_job_changes",
                        raw_data={
                            "endpoint": "/workers?jobChange",
                            "tenant": tenant,
                            "response": job_changes,
                        },
                        observed_at=datetime.now(timezone.utc),
                    ))
            except Exception as e:
                log.debug("Workday job changes failed: %s", e)
                result.errors.append(f"job_changes: {e}")

        finally:
            client.close()

        result.complete()
        return result

    def _get_oauth_token(self) -> str:
        """Obtain OAuth 2.0 access token using client credentials grant."""
        import httpx

        tenant = self.config.settings["tenant"]
        token_url = f"https://wd2-impl-services1.workday.com/ccx/oauth2/{tenant}/token"
        client_id = self.get_secret("WLK_WORKDAY_CLIENT_ID")
        client_secret = self.get_secret("WLK_WORKDAY_CLIENT_SECRET")

        resp = httpx.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _paginate(self, client, endpoint: str, params: dict) -> list:
        """Paginate Workday REST API using offset/limit."""
        all_items: list = []
        offset = 0
        limit = int(params.get("limit", "100"))
        current_params = dict(params)

        while True:
            current_params["offset"] = str(offset)
            resp = client.get(endpoint, params=current_params)
            resp.raise_for_status()
            body = resp.json()

            data = body.get("data", [])
            if isinstance(data, list):
                all_items.extend(data)
            else:
                all_items.append(data)

            total = body.get("total", 0)
            offset += limit
            if offset >= total or not data:
                break

        return all_items

    def _fetch_custom_report(self, client, report_name: str) -> list:
        """Fetch a Workday custom report by name."""
        resp = client.get(
            f"/customreport/{report_name}",
            params={"format": "json"},
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("Report_Entry", [])


# Register
registry.register("workday", WorkdayConnector)
