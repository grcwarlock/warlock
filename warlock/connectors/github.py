"""GitHub connector — Layer 1 implementation for CI/CD and code security.

Collects repos, branch protections, audit log, Dependabot alerts, and
secret scanning alerts from the GitHub REST API.
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

GITHUB_BASE_URL = "https://api.github.com"


class GitHubConnector(BaseConnector):
    """Collects CI/CD and code security telemetry from GitHub REST APIs."""

    def validate(self) -> list[str]:
        errors = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            errors.append("httpx not installed. Install with: pip install warlock[github]")
        if not self.get_secret("WLK_GITHUB_TOKEN"):
            errors.append("WLK_GITHUB_TOKEN env var is not set")
        if not self.config.settings.get("org"):
            errors.append("'org' must be set in connector settings")
        return errors

    def health_check(self) -> bool:
        try:
            import httpx

            token = self.get_secret("WLK_GITHUB_TOKEN")
            resp = httpx.get(
                f"{GITHUB_BASE_URL}/user",
                headers=self._headers(token),
                timeout=self.config.timeout_seconds,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        import httpx

        result = ConnectorResult(
            connector_name=self.name,
            source="github",
            source_type=SourceType.CODE,
            provider="github",
        )

        org = self.config.settings["org"]
        token = self.get_secret("WLK_GITHUB_TOKEN")
        headers = self._headers(token)

        client = httpx.Client(
            base_url=GITHUB_BASE_URL,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )

        try:
            # 1. Repos
            repos = []
            try:
                repos = self._paginate(
                    client,
                    f"/orgs/{org}/repos",
                    params={"per_page": "100"},
                )
                result.events.append(
                    RawEventData(
                        source="github",
                        source_type=SourceType.CODE,
                        provider="github",
                        event_type="github_repos",
                        raw_data={
                            "endpoint": f"/orgs/{org}/repos",
                            "org": org,
                            "response": repos,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("GitHub repos failed: %s", e)
                result.errors.append(f"repos: {e}")

            # 2. Branch protections (per repo, default branch)
            try:
                protections = []
                for repo in repos[:100]:  # cap to avoid rate limits
                    repo_name = repo.get("full_name", "")
                    default_branch = repo.get("default_branch", "main")
                    if not repo_name:
                        continue
                    try:
                        resp = client.get(
                            f"/repos/{repo_name}/branches/{default_branch}/protection",
                        )
                        if resp.status_code == 200:
                            protection = resp.json()
                            protection["_repo"] = repo_name
                            protection["_branch"] = default_branch
                            protections.append(protection)
                        elif resp.status_code == 404:
                            # No branch protection
                            protections.append(
                                {
                                    "_repo": repo_name,
                                    "_branch": default_branch,
                                    "_unprotected": True,
                                }
                            )
                    except Exception:
                        pass

                if protections:
                    result.events.append(
                        RawEventData(
                            source="github",
                            source_type=SourceType.CODE,
                            provider="github",
                            event_type="github_branch_protections",
                            raw_data={
                                "endpoint": "/repos/{owner}/{repo}/branches/{branch}/protection",
                                "org": org,
                                "response": protections,
                            },
                            observed_at=datetime.now(timezone.utc),
                        )
                    )
            except Exception as e:
                log.debug("GitHub branch protections failed: %s", e)
                result.errors.append(f"branch_protections: {e}")

            # 3. Audit log
            try:
                audit_events = self._paginate(
                    client,
                    f"/orgs/{org}/audit-log",
                    params={"per_page": "100", "include": "all"},
                )
                result.events.append(
                    RawEventData(
                        source="github",
                        source_type=SourceType.CODE,
                        provider="github",
                        event_type="github_audit_log",
                        raw_data={
                            "endpoint": f"/orgs/{org}/audit-log",
                            "org": org,
                            "response": audit_events,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("GitHub audit log failed: %s", e)
                result.errors.append(f"audit_log: {e}")

            # 4. Dependabot alerts
            try:
                dependabot = self._paginate(
                    client,
                    f"/orgs/{org}/dependabot/alerts",
                    params={"per_page": "100", "state": "open"},
                )
                result.events.append(
                    RawEventData(
                        source="github",
                        source_type=SourceType.CODE,
                        provider="github",
                        event_type="github_dependabot_alerts",
                        raw_data={
                            "endpoint": f"/orgs/{org}/dependabot/alerts",
                            "org": org,
                            "response": dependabot,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("GitHub dependabot alerts failed: %s", e)
                result.errors.append(f"dependabot_alerts: {e}")

            # 5. Secret scanning alerts
            try:
                secrets = self._paginate(
                    client,
                    f"/orgs/{org}/secret-scanning/alerts",
                    params={"per_page": "100", "state": "open"},
                )
                result.events.append(
                    RawEventData(
                        source="github",
                        source_type=SourceType.CODE,
                        provider="github",
                        event_type="github_secret_scanning_alerts",
                        raw_data={
                            "endpoint": f"/orgs/{org}/secret-scanning/alerts",
                            "org": org,
                            "response": secrets,
                        },
                        observed_at=datetime.now(timezone.utc),
                    )
                )
            except Exception as e:
                log.debug("GitHub secret scanning alerts failed: %s", e)
                result.errors.append(f"secret_scanning_alerts: {e}")

        finally:
            client.close()

        result.complete()
        return result

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _paginate(self, client, endpoint: str, params: dict) -> list:
        """Follow GitHub link-header pagination."""
        all_items: list = []
        url = endpoint
        current_params = dict(params)

        while url:
            resp = client.get(url, params=current_params)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                all_items.extend(data)
            else:
                all_items.append(data)

            # GitHub pagination via Link header
            url = None
            current_params = {}
            link_header = resp.headers.get("link", "")
            for part in link_header.split(","):
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>")
                    if url.startswith("https://"):
                        from urllib.parse import urlparse

                        parsed = urlparse(url)
                        url = parsed.path + ("?" + parsed.query if parsed.query else "")
                    break

        return all_items


# Register
registry.register("github", GitHubConnector)
