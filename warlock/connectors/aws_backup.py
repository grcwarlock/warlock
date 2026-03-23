"""AWS Backup connector — collects backup plans, vaults, and job status."""

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

AWS_BACKUP_ENDPOINTS: list[tuple[str, str]] = [
    ("/backup/plans", "aws_backup_plans"),
    ("/backup/vaults", "aws_backup_vaults"),
    ("/backup/jobs", "aws_backup_jobs"),
]


class AWSBackupConnector(BaseConnector):
    """Collects AWS Backup plan, vault, and job telemetry via AWS REST API."""

    def validate(self) -> list[str]:
        errors: list[str] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed")
        if not self.get_secret("AWS_ACCESS_KEY_ID"):
            errors.append("AWS_ACCESS_KEY_ID env var is not set")
        if not self.get_secret("AWS_SECRET_ACCESS_KEY"):
            errors.append("AWS_SECRET_ACCESS_KEY env var is not set")
        return errors

    def health_check(self) -> bool:
        try:
            client = self._build_client()
            region = self.config.settings.get("region", "us-east-1")
            base_url = f"https://backup.{region}.amazonaws.com"
            resp = client.get(f"{base_url}/backup/vaults", params={"maxResults": "1"})
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_backup",
            source_type=SourceType.BACKUP,
            provider="aws_backup",
        )

        region = self.config.settings.get("region", "us-east-1")
        base_url = f"https://backup.{region}.amazonaws.com"
        client = self._build_client()

        try:
            for path, event_type in AWS_BACKUP_ENDPOINTS:
                try:
                    data = self._paginate(client, f"{base_url}{path}", event_type)
                    result.events.append(
                        RawEventData(
                            source="aws_backup",
                            source_type=SourceType.BACKUP,
                            provider="aws_backup",
                            event_type=event_type,
                            raw_data={
                                "endpoint": path,
                                "region": region,
                                "response": data,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception as e:
                    log.debug("AWS Backup %s failed: %s", path, e)
                    result.errors.append(f"{path}: {e}")
        finally:
            client.close()

        result.complete()
        return result

    def _build_client(self) -> object:
        """Build an httpx client with AWS SigV4-like auth headers (simplified)."""
        import httpx

        access_key = self.get_secret("AWS_ACCESS_KEY_ID")
        session_token = self.get_secret("AWS_SESSION_TOKEN")
        headers: dict[str, str] = {"Accept": "application/json"}
        if session_token:
            headers["X-Amz-Security-Token"] = session_token
        # In production, full SigV4 signing is required; mock connectors use env-injected base_url.
        return httpx.Client(
            headers=headers,
            timeout=self.config.timeout_seconds,
            auth=_AwsAuth(
                access_key=access_key,
                secret_key=self.get_secret("AWS_SECRET_ACCESS_KEY"),
                region=self.config.settings.get("region", "us-east-1"),
                service="backup",
            ),
        )

    def _paginate(self, client: object, url: str, event_type: str) -> list:
        """Paginate AWS Backup responses using nextToken."""
        all_items: list = []
        params: dict[str, str] = {"maxResults": "100"}

        _list_key_map = {
            "aws_backup_plans": "BackupPlansList",
            "aws_backup_vaults": "BackupVaultList",
            "aws_backup_jobs": "BackupJobs",
        }
        list_key = _list_key_map.get(event_type, "")

        while True:
            resp = client.get(url, params=params)  # type: ignore[attr-defined]
            resp.raise_for_status()
            body = resp.json()
            items = body.get(list_key, [])
            all_items.extend(items)
            next_token = body.get("NextToken")
            if not next_token:
                break
            params["nextToken"] = next_token

        return all_items


class _AwsAuth:
    """Minimal AWS auth placeholder; real deployments use boto3/botocore SigV4."""

    def __init__(self, access_key: str, secret_key: str, region: str, service: str) -> None:
        self._access_key = access_key
        self._secret_key = secret_key
        self._region = region
        self._service = service

    def __call__(self, request: object) -> object:  # type: ignore[override]
        # Attach a minimal Authorization header so mock endpoints can identify the caller.
        # Real SigV4 signing requires botocore — avoided per no-new-deps constraint.
        if hasattr(request, "headers"):
            request.headers["X-Amz-Access-Key-Id"] = self._access_key  # type: ignore[index]
        return request


registry.register("aws_backup", AWSBackupConnector)
