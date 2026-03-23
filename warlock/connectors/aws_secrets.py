"""AWS Secrets Manager connector — Layer 1 implementation for CLOUD.

Collects secrets metadata (never values) from AWS Secrets Manager using
AWS credentials. Only the secret name, ARN, rotation status, and last
rotation date are collected — never the secret payload.
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

DEFAULT_REGION = "us-east-1"


class AwsSecretsConnector(BaseConnector):
    """Collects secrets metadata from AWS Secrets Manager.

    Security note: Only metadata is collected. Secret values are never
    fetched, logged, or included in any event payload.
    """

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
            secrets = self._list_secrets(max_results=1)
            return isinstance(secrets, list)
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_secrets",
            source_type=SourceType.CLOUD,
            provider="aws_secrets",
        )

        region = self.config.settings.get("region", DEFAULT_REGION)

        try:
            secrets = self._list_secrets(region=region)
            result.events.append(
                RawEventData(
                    source="aws_secrets",
                    source_type=SourceType.CLOUD,
                    provider="aws_secrets",
                    event_type="aws_secrets_metadata",
                    raw_data={
                        "region": region,
                        "response": secrets,
                    },
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("AWS Secrets Manager collection failed: %s", e)
            result.errors.append(str(e))

        result.complete()
        return result

    def _list_secrets(self, max_results: int = 100, region: str | None = None) -> list[dict]:
        """List secrets metadata from AWS Secrets Manager.

        Intentionally only retrieves metadata fields — Name, ARN,
        RotationEnabled, LastRotatedDate, LastChangedDate, Description.
        Secret values are never requested.
        """
        import httpx

        _region = region or self.config.settings.get("region", DEFAULT_REGION)
        access_key = self.get_secret("AWS_ACCESS_KEY_ID")
        secret_key = self.get_secret("AWS_SECRET_ACCESS_KEY")
        endpoint_url = self.config.settings.get(
            "endpoint_url", f"https://secretsmanager.{_region}.amazonaws.com"
        )

        all_secrets: list[dict] = []
        next_token: str | None = None

        while True:
            headers = {
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": "secretsmanager.ListSecrets",
                "X-Aws-Access-Key-Id": access_key,
                "X-Aws-Secret-Access-Key": secret_key,
            }
            body: dict = {"MaxResults": max_results}
            if next_token:
                body["NextToken"] = next_token

            resp = httpx.post(
                endpoint_url,
                headers=headers,
                json=body,
                timeout=self.config.timeout_seconds,
            )
            resp.raise_for_status()
            data = resp.json()

            secrets = data.get("SecretList", [])
            # Strip any values that could contain secret data (defensive)
            safe_secrets = [
                {
                    k: v
                    for k, v in s.items()
                    if k
                    not in (
                        "SecretString",
                        "SecretBinary",
                        "VersionIdsToStages",
                    )
                }
                for s in secrets
            ]
            all_secrets.extend(safe_secrets)

            next_token = data.get("NextToken")
            if not next_token or len(secrets) < max_results:
                break

        return all_secrets


# Register
registry.register("aws_secrets", AwsSecretsConnector)
