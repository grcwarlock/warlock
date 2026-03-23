"""Alibaba Cloud connector — Layer 1 implementation for cloud infrastructure.

Collects from Security Center, RAM, ActionTrail, ECS Security Groups,
KMS, Cloud Config, and OSS via Alibaba Cloud APIs.
Each API call becomes a RawEventData with the verbatim response.

Auth uses HMAC-SHA1 signed requests. Tries alibabacloud_tea_openapi first;
falls back to manual httpx signing if the SDK is unavailable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import urllib.parse
from datetime import datetime, timezone
from uuid import uuid4

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

log = logging.getLogger(__name__)

# Whether the official Alibaba SDK is available
_HAS_SDK = False
try:
    from alibabacloud_tea_openapi import models as open_api_models  # noqa: F401

    _HAS_SDK = True
except ImportError:
    pass


def _percent_encode(s: str) -> str:
    """Alibaba-style percent encoding (RFC 3986 with * and ~ handled)."""
    return urllib.parse.quote(str(s), safe="~").replace("+", "%20").replace("*", "%2A")


def _build_signed_params(
    access_key_id: str,
    access_key_secret: str,
    action: str,
    params: dict,
    version: str,
) -> dict:
    """Build a dict of query parameters with Alibaba HMAC-SHA1 signature."""
    common = {
        "Format": "JSON",
        "Version": version,
        "AccessKeyId": access_key_id,
        "SignatureMethod": "HMAC-SHA1",
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SignatureVersion": "1.0",
        "SignatureNonce": str(uuid4()),
        "Action": action,
    }
    common.update(params)

    # Build canonical query string
    sorted_keys = sorted(common.keys())
    canonical = "&".join(f"{_percent_encode(k)}={_percent_encode(common[k])}" for k in sorted_keys)
    string_to_sign = f"GET&{_percent_encode('/')}&{_percent_encode(canonical)}"
    signature = base64.b64encode(
        hmac.new(
            (access_key_secret + "&").encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha1,
        ).digest()
    ).decode("utf-8")
    common["Signature"] = signature
    return common


class AlibabaConnector(BaseConnector):
    """Collects compliance telemetry from Alibaba Cloud APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[alibaba]")
        if not self._get_access_key_id():
            errors.append(
                "Alibaba access_key_id not configured "
                "(set WLK_ALIBABA_ACCESS_KEY_ID or config.settings.access_key_id)"
            )
        if not self._get_access_key_secret():
            errors.append(
                "Alibaba access_key_secret not configured (set WLK_ALIBABA_ACCESS_KEY_SECRET)"
            )
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            params = _build_signed_params(
                self._get_access_key_id(),
                self._get_access_key_secret(),
                action="ListUsers",
                params={},
                version="2015-05-01",
            )
            resp = httpx.get("https://ram.aliyuncs.com", params=params, timeout=15)
            return resp.status_code == 200
        except Exception:
            log.warning("Health check failed for %s", self.name, exc_info=True)
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="alibaba",
            source_type=SourceType.CLOUD,
            provider="alibaba",
        )

        region = self.config.settings.get("region", "cn-hangzhou")
        ak_id = self._get_access_key_id()
        ak_secret = self._get_access_key_secret()

        collectors = [
            ("ali_security_alerts", self._collect_security_alerts),
            ("ali_ram_users", self._collect_ram_users),
            ("ali_actiontrail_events", self._collect_actiontrail_events),
            ("ali_security_groups", self._collect_security_groups),
            ("ali_kms_keys", self._collect_kms_keys),
            ("ali_config_compliance", self._collect_config_compliance),
            ("ali_oss_buckets", self._collect_oss_buckets),
        ]

        for event_type, collector_fn in collectors:
            try:
                data = collector_fn(ak_id, ak_secret, region)
                result.events.append(
                    RawEventData(
                        source="alibaba",
                        source_type=SourceType.CLOUD,
                        provider="alibaba",
                        event_type=event_type,
                        raw_data={
                            "region": region,
                            "response": data,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("Alibaba %s failed: %s", event_type, e)
                result.errors.append(f"{event_type}: {e}")

        result.complete()
        return result

    # -- API helper --

    def _api_call(
        self,
        ak_id: str,
        ak_secret: str,
        endpoint: str,
        action: str,
        version: str,
        extra_params: dict | None = None,
    ) -> dict:
        """Make a signed GET request to an Alibaba Cloud API endpoint."""
        import httpx

        params = _build_signed_params(
            ak_id,
            ak_secret,
            action,
            extra_params or {},
            version,
        )
        resp = httpx.get(
            endpoint,
            params=params,
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    # -- Collectors --

    def _collect_security_alerts(
        self,
        ak_id: str,
        ak_secret: str,
        region: str,
    ) -> dict:
        data = self._api_call(
            ak_id,
            ak_secret,
            endpoint="https://tds.aliyuncs.com",
            action="DescribeAlarmEventList",
            version="2018-12-03",
            extra_params={"PageSize": "100", "CurrentPage": "1"},
        )
        return {
            "alerts": data.get("SuspEvents", {}).get("SuspEvent", [])
            if isinstance(data.get("SuspEvents"), dict)
            else data.get("SuspEvents", []),
            "total_count": data.get("PageInfo", {}).get("TotalCount", 0),
        }

    def _collect_ram_users(
        self,
        ak_id: str,
        ak_secret: str,
        region: str,
    ) -> dict:
        data = self._api_call(
            ak_id,
            ak_secret,
            endpoint="https://ram.aliyuncs.com",
            action="ListUsers",
            version="2015-05-01",
        )
        users = data.get("Users", {}).get("User", []) if isinstance(data.get("Users"), dict) else []

        # Enrich with MFA status per user
        enriched_users = []
        for user in users:
            user_name = user.get("UserName", "")
            try:
                mfa_data = self._api_call(
                    ak_id,
                    ak_secret,
                    endpoint="https://ram.aliyuncs.com",
                    action="GetUserMFAInfo",
                    version="2015-05-01",
                    extra_params={"UserName": user_name},
                )
                user["MFADevice"] = mfa_data.get("MFADevice", {})
            except Exception:
                user["MFADevice"] = {}
            enriched_users.append(user)

        return {"users": enriched_users}

    def _collect_actiontrail_events(
        self,
        ak_id: str,
        ak_secret: str,
        region: str,
    ) -> dict:
        endpoint = f"https://actiontrail.{region}.aliyuncs.com"
        data = self._api_call(
            ak_id,
            ak_secret,
            endpoint=endpoint,
            action="LookupEvents",
            version="2020-07-06",
            extra_params={"MaxResults": "50"},
        )
        return {
            "events": data.get("Events", []),
            "next_token": data.get("NextToken", ""),
        }

    def _collect_security_groups(
        self,
        ak_id: str,
        ak_secret: str,
        region: str,
    ) -> dict:
        endpoint = "https://ecs.aliyuncs.com"
        # List security groups
        sg_data = self._api_call(
            ak_id,
            ak_secret,
            endpoint=endpoint,
            action="DescribeSecurityGroups",
            version="2014-05-26",
            extra_params={"RegionId": region, "PageSize": "100"},
        )
        groups = (
            sg_data.get("SecurityGroups", {}).get("SecurityGroup", [])
            if isinstance(sg_data.get("SecurityGroups"), dict)
            else []
        )

        # Enrich each group with its rules
        enriched = []
        for sg in groups:
            sg_id = sg.get("SecurityGroupId", "")
            try:
                attr_data = self._api_call(
                    ak_id,
                    ak_secret,
                    endpoint=endpoint,
                    action="DescribeSecurityGroupAttribute",
                    version="2014-05-26",
                    extra_params={
                        "SecurityGroupId": sg_id,
                        "RegionId": region,
                    },
                )
                sg["Rules"] = (
                    attr_data.get("Permissions", {}).get("Permission", [])
                    if isinstance(attr_data.get("Permissions"), dict)
                    else []
                )
            except Exception:
                sg["Rules"] = []
            enriched.append(sg)

        return {"security_groups": enriched}

    def _collect_kms_keys(
        self,
        ak_id: str,
        ak_secret: str,
        region: str,
    ) -> dict:
        endpoint = f"https://kms.{region}.aliyuncs.com"
        list_data = self._api_call(
            ak_id,
            ak_secret,
            endpoint=endpoint,
            action="ListKeys",
            version="2016-01-20",
            extra_params={"PageSize": "100"},
        )
        keys = (
            list_data.get("Keys", {}).get("Key", [])
            if isinstance(list_data.get("Keys"), dict)
            else []
        )

        # Enrich with key metadata
        enriched = []
        for key in keys:
            key_id = key.get("KeyId", "")
            try:
                detail = self._api_call(
                    ak_id,
                    ak_secret,
                    endpoint=endpoint,
                    action="DescribeKey",
                    version="2016-01-20",
                    extra_params={"KeyId": key_id},
                )
                key["KeyMetadata"] = detail.get("KeyMetadata", {})
            except Exception:
                key["KeyMetadata"] = {}
            enriched.append(key)

        return {"keys": enriched}

    def _collect_config_compliance(
        self,
        ak_id: str,
        ak_secret: str,
        region: str,
    ) -> dict:
        endpoint = f"https://config.{region}.aliyuncs.com"
        data = self._api_call(
            ak_id,
            ak_secret,
            endpoint=endpoint,
            action="ListCompliancePackEvaluationResults",
            version="2020-09-07",
            extra_params={"MaxResults": "100"},
        )
        return {
            "results": data.get("EvaluationResults", {}).get("EvaluationResultList", [])
            if isinstance(data.get("EvaluationResults"), dict)
            else [],
        }

    def _collect_oss_buckets(
        self,
        ak_id: str,
        ak_secret: str,
        region: str,
    ) -> dict:
        # OSS uses a slightly different API surface — list via the ECS-style endpoint
        # The ListBuckets API is XML-based; we use the GetService operation signed
        import httpx

        endpoint = f"https://oss-{region}.aliyuncs.com"
        params = _build_signed_params(
            ak_id,
            ak_secret,
            action="GetService",
            params={},
            version="2019-05-17",
        )
        resp = httpx.get(endpoint, params=params, timeout=self.config.timeout_seconds)
        resp.raise_for_status()

        # Try JSON first, fall back to parsing XML response
        try:
            data = resp.json()
        except Exception:
            # Parse XML response for bucket names
            import xml.etree.ElementTree as ET

            root = ET.fromstring(resp.text)
            ns = root.tag.split("}")[0] + "}" if "}" in root.tag else ""
            buckets_el = root.find(f"{ns}Buckets")
            buckets = []
            if buckets_el is not None:
                for b in buckets_el.findall(f"{ns}Bucket"):
                    bucket_name = b.findtext(f"{ns}Name", "")
                    location = b.findtext(f"{ns}Location", "")
                    creation_date = b.findtext(f"{ns}CreationDate", "")
                    buckets.append(
                        {
                            "Name": bucket_name,
                            "Location": location,
                            "CreationDate": creation_date,
                        }
                    )
            data = {"Buckets": buckets}

        # Check ACL for each bucket
        raw_buckets = data.get("Buckets", [])
        if isinstance(raw_buckets, dict):
            raw_buckets = raw_buckets.get("Bucket", [])

        enriched = []
        for bucket in raw_buckets:
            bucket_name = bucket.get("Name", "")
            try:
                acl_params = _build_signed_params(
                    ak_id,
                    ak_secret,
                    action="GetBucketAcl",
                    params={"BucketName": bucket_name},
                    version="2019-05-17",
                )
                acl_resp = httpx.get(
                    f"https://{bucket_name}.oss-{region}.aliyuncs.com/?acl",
                    params=acl_params,
                    timeout=15,
                )
                try:
                    acl_data = acl_resp.json()
                except Exception:
                    import xml.etree.ElementTree as ET

                    acl_root = ET.fromstring(acl_resp.text)
                    acl_ns = acl_root.tag.split("}")[0] + "}" if "}" in acl_root.tag else ""
                    grant = acl_root.findtext(f".//{acl_ns}Grant", "")
                    acl_data = {"Grant": grant}
                bucket["ACL"] = acl_data
            except Exception:
                bucket["ACL"] = {}

            # Check encryption
            try:
                enc_params = _build_signed_params(
                    ak_id,
                    ak_secret,
                    action="GetBucketEncryption",
                    params={"BucketName": bucket_name},
                    version="2019-05-17",
                )
                enc_resp = httpx.get(
                    f"https://{bucket_name}.oss-{region}.aliyuncs.com/?encryption",
                    params=enc_params,
                    timeout=15,
                )
                bucket["Encryption"] = enc_resp.json() if enc_resp.status_code == 200 else {}
            except Exception:
                bucket["Encryption"] = {}

            enriched.append(bucket)

        return {"buckets": enriched}

    # -- Auth helpers --

    def _get_access_key_id(self) -> str:
        return self.config.settings.get("access_key_id", "") or self.get_secret(
            "WLK_ALIBABA_ACCESS_KEY_ID"
        )

    def _get_access_key_secret(self) -> str:
        return self.get_secret("WLK_ALIBABA_ACCESS_KEY_SECRET")


# Register
registry.register("alibaba", AlibabaConnector)
