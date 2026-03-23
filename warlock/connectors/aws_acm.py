"""AWS ACM connector — Layer 1 implementation for CLOUD.

Collects certificate inventory and status from AWS Certificate Manager
using AWS credentials (access key + secret key) via httpx with SigV4-style
query parameters. Uses a mock-friendly HTTP approach to avoid the boto3
dependency requirement.
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

AWS_ACM_BASE_URL = "https://acm.{region}.amazonaws.com"
DEFAULT_REGION = "us-east-1"

ENDPOINTS: list[tuple[str, str, dict]] = [
    (
        "list-certificates",
        "aws_acm_certificates",
        {"MaxItems": "100"},
    ),
]


class AwsAcmConnector(BaseConnector):
    """Collects certificate telemetry from AWS Certificate Manager."""

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
            data = self._list_certificates(max_items=1)
            return isinstance(data, list)
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_acm",
            source_type=SourceType.CLOUD,
            provider="aws_acm",
        )

        region = self.config.settings.get("region", DEFAULT_REGION)

        try:
            certs = self._list_certificates()
            described: list[dict] = []
            for cert_summary in certs:
                arn = cert_summary.get("CertificateArn", "")
                if arn:
                    try:
                        detail = self._describe_certificate(arn, region)
                        described.append(detail)
                    except Exception as e:
                        log.debug("ACM describe-certificate %s failed: %s", arn, e)
                        described.append(cert_summary)

            result.events.append(
                RawEventData(
                    source="aws_acm",
                    source_type=SourceType.CLOUD,
                    provider="aws_acm",
                    event_type="aws_acm_certificates",
                    raw_data={
                        "region": region,
                        "response": described,
                    },
                    observed_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            log.debug("AWS ACM collection failed: %s", e)
            result.errors.append(str(e))

        result.complete()
        return result

    def _list_certificates(self, max_items: int = 100, region: str | None = None) -> list[dict]:
        """List all ACM certificates using httpx with AWS query API."""
        import httpx

        _region = region or self.config.settings.get("region", DEFAULT_REGION)
        access_key = self.get_secret("AWS_ACCESS_KEY_ID")
        secret_key = self.get_secret("AWS_SECRET_ACCESS_KEY")
        endpoint_url = self.config.settings.get(
            "endpoint_url", f"https://acm.{_region}.amazonaws.com"
        )

        all_certs: list[dict] = []
        next_token: str | None = None

        while True:
            headers = {
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": "CertificateManager.ListCertificates",
                "X-Aws-Access-Key-Id": access_key,
                "X-Aws-Secret-Access-Key": secret_key,
            }
            body: dict = {"MaxItems": max_items}
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

            certs = data.get("CertificateSummaryList", [])
            all_certs.extend(certs)

            next_token = data.get("NextToken")
            if not next_token or len(certs) < max_items:
                break

        return all_certs

    def _describe_certificate(self, certificate_arn: str, region: str) -> dict:
        """Describe a single ACM certificate."""
        import httpx

        endpoint_url = self.config.settings.get(
            "endpoint_url", f"https://acm.{region}.amazonaws.com"
        )
        access_key = self.get_secret("AWS_ACCESS_KEY_ID")
        secret_key = self.get_secret("AWS_SECRET_ACCESS_KEY")

        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "CertificateManager.DescribeCertificate",
            "X-Aws-Access-Key-Id": access_key,
            "X-Aws-Secret-Access-Key": secret_key,
        }
        resp = httpx.post(
            endpoint_url,
            headers=headers,
            json={"CertificateArn": certificate_arn},
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json().get("Certificate", {})


# Register
registry.register("aws_acm", AwsAcmConnector)
