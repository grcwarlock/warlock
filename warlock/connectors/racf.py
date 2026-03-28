"""IBM RACF connector — z/OS mainframe security (RACF) data collection.

Collects user profiles, group memberships, and access rules from the
z/OS RACF security subsystem via the z/OSMF REST API.
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

RACF_ENDPOINTS: list[tuple[str, str]] = [
    ("/zosmf/security/racf/users", "racf_users"),
    ("/zosmf/security/racf/groups", "racf_groups"),
    ("/zosmf/security/racf/dataset-profiles", "racf_dataset_profiles"),
    ("/zosmf/security/racf/general-resource-profiles", "racf_resource_profiles"),
]


class RACFConnector(BaseConnector):
    """Collects mainframe security data from IBM z/OS RACF via z/OSMF REST API.

    Configuration:
        ZOSMF_BASE_URL: Base URL of the z/OSMF server (e.g. https://zos.example.com:443)
        ZOSMF_USERNAME: z/OSMF user ID with RACF read authority
        ZOSMF_PASSWORD: z/OSMF password

    The connector queries RACF user profiles, group definitions, dataset
    access rules, and general resource profiles for compliance assessment.
    """

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("ZOSMF_BASE_URL"):
            errors.append("ZOSMF_BASE_URL env var is not set")
        if not self.get_secret("ZOSMF_USERNAME"):
            errors.append("ZOSMF_USERNAME env var is not set")
        if not self.get_secret("ZOSMF_PASSWORD"):
            errors.append("ZOSMF_PASSWORD env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            base_url = self.get_secret("ZOSMF_BASE_URL").rstrip("/")
            username = self.get_secret("ZOSMF_USERNAME")
            password = self.get_secret("ZOSMF_PASSWORD")
            resp = httpx.get(
                f"{base_url}/zosmf/info",
                auth=(username, password),
                timeout=15,
                verify=False,  # Many z/OSMF instances use self-signed certs
            )
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="racf",
            source_type=SourceType.IAM,
            provider="racf",
        )

        base_url = self.get_secret("ZOSMF_BASE_URL").rstrip("/")
        username = self.get_secret("ZOSMF_USERNAME")
        password = self.get_secret("ZOSMF_PASSWORD")

        client = httpx.Client(
            base_url=base_url,
            auth=(username, password),
            headers={
                "Accept": "application/json",
                "X-CSRF-ZOSMF-HEADER": "",
            },
            timeout=self.config.timeout_seconds,
            verify=False,  # Many z/OSMF instances use self-signed certs
        )

        try:
            for endpoint, event_type in RACF_ENDPOINTS:
                try:
                    resp = client.get(endpoint)
                    resp.raise_for_status()
                    body = resp.json()

                    items = body.get("items", body.get("profiles", [body]))
                    if not isinstance(items, list):
                        items = [items]

                    result.events.append(
                        RawEventData(
                            source="racf",
                            source_type=SourceType.IAM,
                            provider="racf",
                            event_type=event_type,
                            raw_data={
                                "endpoint": endpoint,
                                "base_url": base_url,
                                "response": items,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("RACF %s failed: %s", endpoint, e)
                    result.errors.append(f"{endpoint}: {e}")
        finally:
            client.close()

        result.complete()
        return result


# Register
registry.register("racf", RACFConnector)
