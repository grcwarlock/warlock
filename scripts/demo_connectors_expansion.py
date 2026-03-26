"""Demo mock connectors for 186 new sources (imported by demo_seed.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import (
    BaseConnector,
    ConnectorResult,
    RawEventData,
    SourceType,
)

NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Heroku
# ---------------------------------------------------------------------------
class DemoHerokuConnector(BaseConnector):
    """Simulates Heroku collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="heroku",
            source_type=SourceType.CLOUD,
            provider="heroku",
        )

        result.events.append(
            RawEventData(
                source="heroku",
                source_type=SourceType.CLOUD,
                provider="heroku",
                event_type="heroku_apps",
                raw_data={
                    "response": [
                        {
                            "id": "HEROKU-001",
                            "name": "Heroku instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HEROKU-002",
                            "name": "Heroku instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HEROKU-003",
                            "name": "Heroku instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HEROKU-004",
                            "name": "Heroku instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="heroku",
                source_type=SourceType.CLOUD,
                provider="heroku",
                event_type="heroku_teams",
                raw_data={
                    "response": [
                        {
                            "id": "HEROKU-001",
                            "name": "Heroku instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HEROKU-002",
                            "name": "Heroku instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HEROKU-003",
                            "name": "Heroku instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HEROKU-004",
                            "name": "Heroku instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="heroku",
                source_type=SourceType.CLOUD,
                provider="heroku",
                event_type="heroku_addons",
                raw_data={
                    "response": [
                        {
                            "id": "HEROKU-001",
                            "name": "Heroku instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HEROKU-002",
                            "name": "Heroku instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HEROKU-003",
                            "name": "Heroku instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HEROKU-004",
                            "name": "Heroku instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Scaleway
# ---------------------------------------------------------------------------
class DemoScalewayConnector(BaseConnector):
    """Simulates Scaleway collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="scaleway",
            source_type=SourceType.CLOUD,
            provider="scaleway",
        )

        result.events.append(
            RawEventData(
                source="scaleway",
                source_type=SourceType.CLOUD,
                provider="scaleway",
                event_type="scaleway_instances",
                raw_data={
                    "response": [
                        {
                            "id": "SCALEWAY-001",
                            "name": "Scaleway instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SCALEWAY-002",
                            "name": "Scaleway instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SCALEWAY-003",
                            "name": "Scaleway instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SCALEWAY-004",
                            "name": "Scaleway instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="scaleway",
                source_type=SourceType.CLOUD,
                provider="scaleway",
                event_type="scaleway_vpcs",
                raw_data={
                    "response": [
                        {
                            "id": "SCALEWAY-001",
                            "name": "Scaleway instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SCALEWAY-002",
                            "name": "Scaleway instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SCALEWAY-003",
                            "name": "Scaleway instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SCALEWAY-004",
                            "name": "Scaleway instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="scaleway",
                source_type=SourceType.CLOUD,
                provider="scaleway",
                event_type="scaleway_api_keys",
                raw_data={
                    "response": [
                        {
                            "id": "SCALEWAY-001",
                            "name": "Scaleway instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SCALEWAY-002",
                            "name": "Scaleway instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SCALEWAY-003",
                            "name": "Scaleway instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SCALEWAY-004",
                            "name": "Scaleway instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
class DemoRenderConnector(BaseConnector):
    """Simulates Render collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="render",
            source_type=SourceType.CLOUD,
            provider="render",
        )

        result.events.append(
            RawEventData(
                source="render",
                source_type=SourceType.CLOUD,
                provider="render",
                event_type="render_services",
                raw_data={
                    "response": [
                        {
                            "id": "RENDER-001",
                            "name": "Render instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RENDER-002",
                            "name": "Render instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RENDER-003",
                            "name": "Render instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "RENDER-004",
                            "name": "Render instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="render",
                source_type=SourceType.CLOUD,
                provider="render",
                event_type="render_deploys",
                raw_data={
                    "response": [
                        {
                            "id": "RENDER-001",
                            "name": "Render instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RENDER-002",
                            "name": "Render instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RENDER-003",
                            "name": "Render instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "RENDER-004",
                            "name": "Render instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="render",
                source_type=SourceType.CLOUD,
                provider="render",
                event_type="render_env_groups",
                raw_data={
                    "response": [
                        {
                            "id": "RENDER-001",
                            "name": "Render instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RENDER-002",
                            "name": "Render instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RENDER-003",
                            "name": "Render instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "RENDER-004",
                            "name": "Render instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Netlify
# ---------------------------------------------------------------------------
class DemoNetlifyConnector(BaseConnector):
    """Simulates Netlify collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="netlify",
            source_type=SourceType.CLOUD,
            provider="netlify",
        )

        result.events.append(
            RawEventData(
                source="netlify",
                source_type=SourceType.CLOUD,
                provider="netlify",
                event_type="netlify_sites",
                raw_data={
                    "response": [
                        {
                            "id": "NETLIFY-001",
                            "name": "Netlify instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NETLIFY-002",
                            "name": "Netlify instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NETLIFY-003",
                            "name": "Netlify instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NETLIFY-004",
                            "name": "Netlify instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="netlify",
                source_type=SourceType.CLOUD,
                provider="netlify",
                event_type="netlify_deploys",
                raw_data={
                    "response": [
                        {
                            "id": "NETLIFY-001",
                            "name": "Netlify instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NETLIFY-002",
                            "name": "Netlify instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NETLIFY-003",
                            "name": "Netlify instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NETLIFY-004",
                            "name": "Netlify instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="netlify",
                source_type=SourceType.CLOUD,
                provider="netlify",
                event_type="netlify_accounts",
                raw_data={
                    "response": [
                        {
                            "id": "NETLIFY-001",
                            "name": "Netlify instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NETLIFY-002",
                            "name": "Netlify instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NETLIFY-003",
                            "name": "Netlify instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NETLIFY-004",
                            "name": "Netlify instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Vercel
# ---------------------------------------------------------------------------
class DemoVercelCloudConnector(BaseConnector):
    """Simulates Vercel collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="vercel_cloud",
            source_type=SourceType.CLOUD,
            provider="vercel_cloud",
        )

        result.events.append(
            RawEventData(
                source="vercel_cloud",
                source_type=SourceType.CLOUD,
                provider="vercel_cloud",
                event_type="vercel_projects",
                raw_data={
                    "response": [
                        {
                            "id": "VERCEL_CLOUD-001",
                            "name": "Vercel instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "VERCEL_CLOUD-002",
                            "name": "Vercel instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "VERCEL_CLOUD-003",
                            "name": "Vercel instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "VERCEL_CLOUD-004",
                            "name": "Vercel instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vercel_cloud",
                source_type=SourceType.CLOUD,
                provider="vercel_cloud",
                event_type="vercel_deployments",
                raw_data={
                    "response": [
                        {
                            "id": "VERCEL_CLOUD-001",
                            "name": "Vercel instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "VERCEL_CLOUD-002",
                            "name": "Vercel instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "VERCEL_CLOUD-003",
                            "name": "Vercel instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "VERCEL_CLOUD-004",
                            "name": "Vercel instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vercel_cloud",
                source_type=SourceType.CLOUD,
                provider="vercel_cloud",
                event_type="vercel_teams",
                raw_data={
                    "response": [
                        {
                            "id": "VERCEL_CLOUD-001",
                            "name": "Vercel instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "VERCEL_CLOUD-002",
                            "name": "Vercel instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "VERCEL_CLOUD-003",
                            "name": "Vercel instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "VERCEL_CLOUD-004",
                            "name": "Vercel instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# MongoDB Atlas
# ---------------------------------------------------------------------------
class DemoMongoDBAtlasConnector(BaseConnector):
    """Simulates MongoDB Atlas collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="mongodb_atlas",
            source_type=SourceType.CLOUD,
            provider="mongodb_atlas",
        )

        result.events.append(
            RawEventData(
                source="mongodb_atlas",
                source_type=SourceType.CLOUD,
                provider="mongodb_atlas",
                event_type="atlas_projects",
                raw_data={
                    "response": [
                        {
                            "id": "MONGODB_ATLAS-001",
                            "name": "MongoDB Atlas instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MONGODB_ATLAS-002",
                            "name": "MongoDB Atlas instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MONGODB_ATLAS-003",
                            "name": "MongoDB Atlas instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MONGODB_ATLAS-004",
                            "name": "MongoDB Atlas instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="mongodb_atlas",
                source_type=SourceType.CLOUD,
                provider="mongodb_atlas",
                event_type="atlas_clusters",
                raw_data={
                    "response": [
                        {
                            "id": "MONGODB_ATLAS-001",
                            "name": "MongoDB Atlas instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MONGODB_ATLAS-002",
                            "name": "MongoDB Atlas instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MONGODB_ATLAS-003",
                            "name": "MongoDB Atlas instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MONGODB_ATLAS-004",
                            "name": "MongoDB Atlas instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="mongodb_atlas",
                source_type=SourceType.CLOUD,
                provider="mongodb_atlas",
                event_type="atlas_events",
                raw_data={
                    "response": [
                        {
                            "id": "MONGODB_ATLAS-001",
                            "name": "MongoDB Atlas instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MONGODB_ATLAS-002",
                            "name": "MongoDB Atlas instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MONGODB_ATLAS-003",
                            "name": "MongoDB Atlas instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MONGODB_ATLAS-004",
                            "name": "MongoDB Atlas instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Supabase
# ---------------------------------------------------------------------------
class DemoSupabaseConnector(BaseConnector):
    """Simulates Supabase collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="supabase",
            source_type=SourceType.CLOUD,
            provider="supabase",
        )

        result.events.append(
            RawEventData(
                source="supabase",
                source_type=SourceType.CLOUD,
                provider="supabase",
                event_type="supabase_projects",
                raw_data={
                    "response": [
                        {
                            "id": "SUPABASE-001",
                            "name": "Supabase instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SUPABASE-002",
                            "name": "Supabase instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SUPABASE-003",
                            "name": "Supabase instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SUPABASE-004",
                            "name": "Supabase instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="supabase",
                source_type=SourceType.CLOUD,
                provider="supabase",
                event_type="supabase_organizations",
                raw_data={
                    "response": [
                        {
                            "id": "SUPABASE-001",
                            "name": "Supabase instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SUPABASE-002",
                            "name": "Supabase instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SUPABASE-003",
                            "name": "Supabase instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SUPABASE-004",
                            "name": "Supabase instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Snowflake
# ---------------------------------------------------------------------------
class DemoSnowflakeConnector(BaseConnector):
    """Simulates Snowflake collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="snowflake",
            source_type=SourceType.DATA_GOVERNANCE,
            provider="snowflake",
        )

        result.events.append(
            RawEventData(
                source="snowflake",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="snowflake",
                event_type="snowflake_databases",
                raw_data={
                    "response": [
                        {
                            "id": "SNOWFLAKE-001",
                            "name": "Snowflake dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SNOWFLAKE-002",
                            "name": "Snowflake dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SNOWFLAKE-003",
                            "name": "Snowflake dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SNOWFLAKE-004",
                            "name": "Snowflake dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="snowflake",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="snowflake",
                event_type="snowflake_users",
                raw_data={
                    "response": [
                        {
                            "id": "SNOWFLAKE-001",
                            "name": "Snowflake dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SNOWFLAKE-002",
                            "name": "Snowflake dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SNOWFLAKE-003",
                            "name": "Snowflake dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SNOWFLAKE-004",
                            "name": "Snowflake dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="snowflake",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="snowflake",
                event_type="snowflake_warehouses",
                raw_data={
                    "response": [
                        {
                            "id": "SNOWFLAKE-001",
                            "name": "Snowflake dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SNOWFLAKE-002",
                            "name": "Snowflake dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SNOWFLAKE-003",
                            "name": "Snowflake dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SNOWFLAKE-004",
                            "name": "Snowflake dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# AWS GovCloud
# ---------------------------------------------------------------------------
class DemoAWSGovCloudConnector(BaseConnector):
    """Simulates AWS GovCloud collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_govcloud",
            source_type=SourceType.CLOUD,
            provider="aws_govcloud",
        )

        result.events.append(
            RawEventData(
                source="aws_govcloud",
                source_type=SourceType.CLOUD,
                provider="aws_govcloud",
                event_type="govcloud_instances",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_GOVCLOUD-001",
                            "name": "AWS GovCloud instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_GOVCLOUD-002",
                            "name": "AWS GovCloud instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_GOVCLOUD-003",
                            "name": "AWS GovCloud instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AWS_GOVCLOUD-004",
                            "name": "AWS GovCloud instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aws_govcloud",
                source_type=SourceType.CLOUD,
                provider="aws_govcloud",
                event_type="govcloud_vpcs",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_GOVCLOUD-001",
                            "name": "AWS GovCloud instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_GOVCLOUD-002",
                            "name": "AWS GovCloud instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_GOVCLOUD-003",
                            "name": "AWS GovCloud instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AWS_GOVCLOUD-004",
                            "name": "AWS GovCloud instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aws_govcloud",
                source_type=SourceType.CLOUD,
                provider="aws_govcloud",
                event_type="govcloud_security_groups",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_GOVCLOUD-001",
                            "name": "AWS GovCloud instance 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_GOVCLOUD-002",
                            "name": "AWS GovCloud instance 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_GOVCLOUD-003",
                            "name": "AWS GovCloud instance 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AWS_GOVCLOUD-004",
                            "name": "AWS GovCloud instance 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# AWS Inspector
# ---------------------------------------------------------------------------
class DemoAWSInspectorConnector(BaseConnector):
    """Simulates AWS Inspector collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_inspector",
            source_type=SourceType.SCANNER,
            provider="aws_inspector",
        )

        result.events.append(
            RawEventData(
                source="aws_inspector",
                source_type=SourceType.SCANNER,
                provider="aws_inspector",
                event_type="inspector_findings",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_INSPECTOR-001",
                            "name": "AWS Inspector finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_INSPECTOR-002",
                            "name": "AWS Inspector finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_INSPECTOR-003",
                            "name": "AWS Inspector finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aws_inspector",
                source_type=SourceType.SCANNER,
                provider="aws_inspector",
                event_type="inspector_coverage",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_INSPECTOR-001",
                            "name": "AWS Inspector finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_INSPECTOR-002",
                            "name": "AWS Inspector finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_INSPECTOR-003",
                            "name": "AWS Inspector finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Akamai
# ---------------------------------------------------------------------------
class DemoAkamaiConnector(BaseConnector):
    """Simulates Akamai collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="akamai",
            source_type=SourceType.NETWORK,
            provider="akamai",
        )

        result.events.append(
            RawEventData(
                source="akamai",
                source_type=SourceType.NETWORK,
                provider="akamai",
                event_type="akamai_security_configs",
                raw_data={
                    "response": [
                        {
                            "id": "AKAMAI-001",
                            "name": "Akamai device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AKAMAI-002",
                            "name": "Akamai device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AKAMAI-003",
                            "name": "Akamai device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="akamai",
                source_type=SourceType.NETWORK,
                provider="akamai",
                event_type="akamai_firewall_rules",
                raw_data={
                    "response": [
                        {
                            "id": "AKAMAI-001",
                            "name": "Akamai device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AKAMAI-002",
                            "name": "Akamai device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AKAMAI-003",
                            "name": "Akamai device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AKAMAI-004",
                            "name": "Akamai device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="akamai",
                source_type=SourceType.NETWORK,
                provider="akamai",
                event_type="akamai_events",
                raw_data={
                    "response": [
                        {
                            "id": "AKAMAI-001",
                            "name": "Akamai device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AKAMAI-002",
                            "name": "Akamai device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AKAMAI-003",
                            "name": "Akamai device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Imperva
# ---------------------------------------------------------------------------
class DemoImpervaConnector(BaseConnector):
    """Simulates Imperva collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="imperva",
            source_type=SourceType.NETWORK,
            provider="imperva",
        )

        result.events.append(
            RawEventData(
                source="imperva",
                source_type=SourceType.NETWORK,
                provider="imperva",
                event_type="imperva_sites",
                raw_data={
                    "response": [
                        {
                            "id": "IMPERVA-001",
                            "name": "Imperva device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "IMPERVA-002",
                            "name": "Imperva device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "IMPERVA-003",
                            "name": "Imperva device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="imperva",
                source_type=SourceType.NETWORK,
                provider="imperva",
                event_type="imperva_waf_rules",
                raw_data={
                    "response": [
                        {
                            "id": "IMPERVA-001",
                            "name": "Imperva device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "IMPERVA-002",
                            "name": "Imperva device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "IMPERVA-003",
                            "name": "Imperva device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "IMPERVA-004",
                            "name": "Imperva device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="imperva",
                source_type=SourceType.NETWORK,
                provider="imperva",
                event_type="imperva_events",
                raw_data={
                    "response": [
                        {
                            "id": "IMPERVA-001",
                            "name": "Imperva device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "IMPERVA-002",
                            "name": "Imperva device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "IMPERVA-003",
                            "name": "Imperva device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# PingOne
# ---------------------------------------------------------------------------
class DemoPingIdentityNewConnector(BaseConnector):
    """Simulates PingOne collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ping_identity_new",
            source_type=SourceType.IAM,
            provider="ping_identity_new",
        )

        result.events.append(
            RawEventData(
                source="ping_identity_new",
                source_type=SourceType.IAM,
                provider="ping_identity_new",
                event_type="pingone_users",
                raw_data={
                    "response": [
                        {
                            "id": "PING_IDENTITY_NEW-001",
                            "name": "PingOne account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PING_IDENTITY_NEW-002",
                            "name": "PingOne account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PING_IDENTITY_NEW-003",
                            "name": "PingOne account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PING_IDENTITY_NEW-004",
                            "name": "PingOne account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ping_identity_new",
                source_type=SourceType.IAM,
                provider="ping_identity_new",
                event_type="pingone_groups",
                raw_data={
                    "response": [
                        {
                            "id": "PING_IDENTITY_NEW-001",
                            "name": "PingOne account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PING_IDENTITY_NEW-002",
                            "name": "PingOne account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PING_IDENTITY_NEW-003",
                            "name": "PingOne account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PING_IDENTITY_NEW-004",
                            "name": "PingOne account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ping_identity_new",
                source_type=SourceType.IAM,
                provider="ping_identity_new",
                event_type="pingone_signon_policies",
                raw_data={
                    "response": [
                        {
                            "id": "PING_IDENTITY_NEW-001",
                            "name": "PingOne account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PING_IDENTITY_NEW-002",
                            "name": "PingOne account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PING_IDENTITY_NEW-003",
                            "name": "PingOne account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PING_IDENTITY_NEW-004",
                            "name": "PingOne account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# LastPass
# ---------------------------------------------------------------------------
class DemoLastPassConnector(BaseConnector):
    """Simulates LastPass collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="lastpass",
            source_type=SourceType.IAM,
            provider="lastpass",
        )

        result.events.append(
            RawEventData(
                source="lastpass",
                source_type=SourceType.IAM,
                provider="lastpass",
                event_type="lastpass_users",
                raw_data={
                    "response": [
                        {
                            "id": "LASTPASS-001",
                            "name": "LastPass account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LASTPASS-002",
                            "name": "LastPass account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LASTPASS-003",
                            "name": "LastPass account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LASTPASS-004",
                            "name": "LastPass account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="lastpass",
                source_type=SourceType.IAM,
                provider="lastpass",
                event_type="lastpass_events",
                raw_data={
                    "response": [
                        {
                            "id": "LASTPASS-001",
                            "name": "LastPass account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LASTPASS-002",
                            "name": "LastPass account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LASTPASS-003",
                            "name": "LastPass account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LASTPASS-004",
                            "name": "LastPass account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Dashlane
# ---------------------------------------------------------------------------
class DemoDashlaneConnector(BaseConnector):
    """Simulates Dashlane collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="dashlane",
            source_type=SourceType.IAM,
            provider="dashlane",
        )

        result.events.append(
            RawEventData(
                source="dashlane",
                source_type=SourceType.IAM,
                provider="dashlane",
                event_type="dashlane_users",
                raw_data={
                    "response": [
                        {
                            "id": "DASHLANE-001",
                            "name": "Dashlane account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DASHLANE-002",
                            "name": "Dashlane account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DASHLANE-003",
                            "name": "Dashlane account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DASHLANE-004",
                            "name": "Dashlane account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dashlane",
                source_type=SourceType.IAM,
                provider="dashlane",
                event_type="dashlane_audit_logs",
                raw_data={
                    "response": [
                        {
                            "id": "DASHLANE-001",
                            "name": "Dashlane account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DASHLANE-002",
                            "name": "Dashlane account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DASHLANE-003",
                            "name": "Dashlane account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DASHLANE-004",
                            "name": "Dashlane account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# NordPass
# ---------------------------------------------------------------------------
class DemoNordPassConnector(BaseConnector):
    """Simulates NordPass collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="nordpass",
            source_type=SourceType.IAM,
            provider="nordpass",
        )

        result.events.append(
            RawEventData(
                source="nordpass",
                source_type=SourceType.IAM,
                provider="nordpass",
                event_type="nordpass_users",
                raw_data={
                    "response": [
                        {
                            "id": "NORDPASS-001",
                            "name": "NordPass account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NORDPASS-002",
                            "name": "NordPass account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NORDPASS-003",
                            "name": "NordPass account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NORDPASS-004",
                            "name": "NordPass account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="nordpass",
                source_type=SourceType.IAM,
                provider="nordpass",
                event_type="nordpass_activity",
                raw_data={
                    "response": [
                        {
                            "id": "NORDPASS-001",
                            "name": "NordPass account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NORDPASS-002",
                            "name": "NordPass account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NORDPASS-003",
                            "name": "NordPass account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NORDPASS-004",
                            "name": "NordPass account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Keeper
# ---------------------------------------------------------------------------
class DemoKeeperConnector(BaseConnector):
    """Simulates Keeper collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="keeper",
            source_type=SourceType.IAM,
            provider="keeper",
        )

        result.events.append(
            RawEventData(
                source="keeper",
                source_type=SourceType.IAM,
                provider="keeper",
                event_type="keeper_users",
                raw_data={
                    "response": [
                        {
                            "id": "KEEPER-001",
                            "name": "Keeper account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KEEPER-002",
                            "name": "Keeper account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KEEPER-003",
                            "name": "Keeper account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KEEPER-004",
                            "name": "Keeper account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="keeper",
                source_type=SourceType.IAM,
                provider="keeper",
                event_type="keeper_events",
                raw_data={
                    "response": [
                        {
                            "id": "KEEPER-001",
                            "name": "Keeper account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KEEPER-002",
                            "name": "Keeper account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KEEPER-003",
                            "name": "Keeper account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KEEPER-004",
                            "name": "Keeper account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="keeper",
                source_type=SourceType.IAM,
                provider="keeper",
                event_type="keeper_vaults",
                raw_data={
                    "response": [
                        {
                            "id": "KEEPER-001",
                            "name": "Keeper account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KEEPER-002",
                            "name": "Keeper account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KEEPER-003",
                            "name": "Keeper account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KEEPER-004",
                            "name": "Keeper account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# AccessOwl
# ---------------------------------------------------------------------------
class DemoAccessOwlConnector(BaseConnector):
    """Simulates AccessOwl collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="accessowl",
            source_type=SourceType.IAM,
            provider="accessowl",
        )

        result.events.append(
            RawEventData(
                source="accessowl",
                source_type=SourceType.IAM,
                provider="accessowl",
                event_type="accessowl_accounts",
                raw_data={
                    "response": [
                        {
                            "id": "ACCESSOWL-001",
                            "name": "AccessOwl account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ACCESSOWL-002",
                            "name": "AccessOwl account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ACCESSOWL-003",
                            "name": "AccessOwl account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ACCESSOWL-004",
                            "name": "AccessOwl account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="accessowl",
                source_type=SourceType.IAM,
                provider="accessowl",
                event_type="accessowl_reviews",
                raw_data={
                    "response": [
                        {
                            "id": "ACCESSOWL-001",
                            "name": "AccessOwl account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ACCESSOWL-002",
                            "name": "AccessOwl account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ACCESSOWL-003",
                            "name": "AccessOwl account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ACCESSOWL-004",
                            "name": "AccessOwl account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Indent
# ---------------------------------------------------------------------------
class DemoIndentConnector(BaseConnector):
    """Simulates Indent collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="indent",
            source_type=SourceType.IAM,
            provider="indent",
        )

        result.events.append(
            RawEventData(
                source="indent",
                source_type=SourceType.IAM,
                provider="indent",
                event_type="indent_petitions",
                raw_data={
                    "response": [
                        {
                            "id": "INDENT-001",
                            "name": "Indent account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INDENT-002",
                            "name": "Indent account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INDENT-003",
                            "name": "Indent account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INDENT-004",
                            "name": "Indent account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="indent",
                source_type=SourceType.IAM,
                provider="indent",
                event_type="indent_resources",
                raw_data={
                    "response": [
                        {
                            "id": "INDENT-001",
                            "name": "Indent account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INDENT-002",
                            "name": "Indent account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INDENT-003",
                            "name": "Indent account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INDENT-004",
                            "name": "Indent account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Saviynt
# ---------------------------------------------------------------------------
class DemoSaviyntConnector(BaseConnector):
    """Simulates Saviynt collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="saviynt",
            source_type=SourceType.IAM,
            provider="saviynt",
        )

        result.events.append(
            RawEventData(
                source="saviynt",
                source_type=SourceType.IAM,
                provider="saviynt",
                event_type="saviynt_users",
                raw_data={
                    "response": [
                        {
                            "id": "SAVIYNT-001",
                            "name": "Saviynt account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SAVIYNT-002",
                            "name": "Saviynt account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SAVIYNT-003",
                            "name": "Saviynt account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SAVIYNT-004",
                            "name": "Saviynt account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="saviynt",
                source_type=SourceType.IAM,
                provider="saviynt",
                event_type="saviynt_entitlements",
                raw_data={
                    "response": [
                        {
                            "id": "SAVIYNT-001",
                            "name": "Saviynt account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SAVIYNT-002",
                            "name": "Saviynt account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SAVIYNT-003",
                            "name": "Saviynt account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SAVIYNT-004",
                            "name": "Saviynt account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="saviynt",
                source_type=SourceType.IAM,
                provider="saviynt",
                event_type="saviynt_access_reviews",
                raw_data={
                    "response": [
                        {
                            "id": "SAVIYNT-001",
                            "name": "Saviynt account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SAVIYNT-002",
                            "name": "Saviynt account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SAVIYNT-003",
                            "name": "Saviynt account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SAVIYNT-004",
                            "name": "Saviynt account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# ConductorOne
# ---------------------------------------------------------------------------
class DemoConductorOneConnector(BaseConnector):
    """Simulates ConductorOne collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="conductorone",
            source_type=SourceType.IAM,
            provider="conductorone",
        )

        result.events.append(
            RawEventData(
                source="conductorone",
                source_type=SourceType.IAM,
                provider="conductorone",
                event_type="conductorone_apps",
                raw_data={
                    "response": [
                        {
                            "id": "CONDUCTORONE-001",
                            "name": "ConductorOne account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CONDUCTORONE-002",
                            "name": "ConductorOne account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CONDUCTORONE-003",
                            "name": "ConductorOne account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CONDUCTORONE-004",
                            "name": "ConductorOne account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="conductorone",
                source_type=SourceType.IAM,
                provider="conductorone",
                event_type="conductorone_users",
                raw_data={
                    "response": [
                        {
                            "id": "CONDUCTORONE-001",
                            "name": "ConductorOne account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CONDUCTORONE-002",
                            "name": "ConductorOne account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CONDUCTORONE-003",
                            "name": "ConductorOne account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CONDUCTORONE-004",
                            "name": "ConductorOne account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="conductorone",
                source_type=SourceType.IAM,
                provider="conductorone",
                event_type="conductorone_entitlements",
                raw_data={
                    "response": [
                        {
                            "id": "CONDUCTORONE-001",
                            "name": "ConductorOne account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CONDUCTORONE-002",
                            "name": "ConductorOne account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CONDUCTORONE-003",
                            "name": "ConductorOne account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CONDUCTORONE-004",
                            "name": "ConductorOne account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# HashiCorp Boundary
# ---------------------------------------------------------------------------
class DemoBoundaryConnector(BaseConnector):
    """Simulates HashiCorp Boundary collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="boundary",
            source_type=SourceType.IAM,
            provider="boundary",
        )

        result.events.append(
            RawEventData(
                source="boundary",
                source_type=SourceType.IAM,
                provider="boundary",
                event_type="boundary_scopes",
                raw_data={
                    "response": [
                        {
                            "id": "BOUNDARY-001",
                            "name": "HashiCorp Boundary account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BOUNDARY-002",
                            "name": "HashiCorp Boundary account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BOUNDARY-003",
                            "name": "HashiCorp Boundary account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BOUNDARY-004",
                            "name": "HashiCorp Boundary account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="boundary",
                source_type=SourceType.IAM,
                provider="boundary",
                event_type="boundary_targets",
                raw_data={
                    "response": [
                        {
                            "id": "BOUNDARY-001",
                            "name": "HashiCorp Boundary account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BOUNDARY-002",
                            "name": "HashiCorp Boundary account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BOUNDARY-003",
                            "name": "HashiCorp Boundary account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BOUNDARY-004",
                            "name": "HashiCorp Boundary account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="boundary",
                source_type=SourceType.IAM,
                provider="boundary",
                event_type="boundary_sessions",
                raw_data={
                    "response": [
                        {
                            "id": "BOUNDARY-001",
                            "name": "HashiCorp Boundary account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BOUNDARY-002",
                            "name": "HashiCorp Boundary account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BOUNDARY-003",
                            "name": "HashiCorp Boundary account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BOUNDARY-004",
                            "name": "HashiCorp Boundary account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Teleport
# ---------------------------------------------------------------------------
class DemoTeleportConnector(BaseConnector):
    """Simulates Teleport collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="teleport",
            source_type=SourceType.IAM,
            provider="teleport",
        )

        result.events.append(
            RawEventData(
                source="teleport",
                source_type=SourceType.IAM,
                provider="teleport",
                event_type="teleport_nodes",
                raw_data={
                    "response": [
                        {
                            "id": "TELEPORT-001",
                            "name": "Teleport account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TELEPORT-002",
                            "name": "Teleport account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TELEPORT-003",
                            "name": "Teleport account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TELEPORT-004",
                            "name": "Teleport account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="teleport",
                source_type=SourceType.IAM,
                provider="teleport",
                event_type="teleport_users",
                raw_data={
                    "response": [
                        {
                            "id": "TELEPORT-001",
                            "name": "Teleport account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TELEPORT-002",
                            "name": "Teleport account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TELEPORT-003",
                            "name": "Teleport account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TELEPORT-004",
                            "name": "Teleport account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="teleport",
                source_type=SourceType.IAM,
                provider="teleport",
                event_type="teleport_sessions",
                raw_data={
                    "response": [
                        {
                            "id": "TELEPORT-001",
                            "name": "Teleport account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TELEPORT-002",
                            "name": "Teleport account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TELEPORT-003",
                            "name": "Teleport account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TELEPORT-004",
                            "name": "Teleport account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# StrongDM
# ---------------------------------------------------------------------------
class DemoStrongDMConnector(BaseConnector):
    """Simulates StrongDM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="strongdm",
            source_type=SourceType.IAM,
            provider="strongdm",
        )

        result.events.append(
            RawEventData(
                source="strongdm",
                source_type=SourceType.IAM,
                provider="strongdm",
                event_type="strongdm_nodes",
                raw_data={
                    "response": [
                        {
                            "id": "STRONGDM-001",
                            "name": "StrongDM account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "STRONGDM-002",
                            "name": "StrongDM account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "STRONGDM-003",
                            "name": "StrongDM account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "STRONGDM-004",
                            "name": "StrongDM account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="strongdm",
                source_type=SourceType.IAM,
                provider="strongdm",
                event_type="strongdm_accounts",
                raw_data={
                    "response": [
                        {
                            "id": "STRONGDM-001",
                            "name": "StrongDM account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "STRONGDM-002",
                            "name": "StrongDM account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "STRONGDM-003",
                            "name": "StrongDM account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "STRONGDM-004",
                            "name": "StrongDM account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="strongdm",
                source_type=SourceType.IAM,
                provider="strongdm",
                event_type="strongdm_activities",
                raw_data={
                    "response": [
                        {
                            "id": "STRONGDM-001",
                            "name": "StrongDM account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "STRONGDM-002",
                            "name": "StrongDM account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "STRONGDM-003",
                            "name": "StrongDM account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "STRONGDM-004",
                            "name": "StrongDM account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Doppler
# ---------------------------------------------------------------------------
class DemoDopplerConnector(BaseConnector):
    """Simulates Doppler collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="doppler",
            source_type=SourceType.IAM,
            provider="doppler",
        )

        result.events.append(
            RawEventData(
                source="doppler",
                source_type=SourceType.IAM,
                provider="doppler",
                event_type="doppler_projects",
                raw_data={
                    "response": [
                        {
                            "id": "DOPPLER-001",
                            "name": "Doppler account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOPPLER-002",
                            "name": "Doppler account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOPPLER-003",
                            "name": "Doppler account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOPPLER-004",
                            "name": "Doppler account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="doppler",
                source_type=SourceType.IAM,
                provider="doppler",
                event_type="doppler_configs",
                raw_data={
                    "response": [
                        {
                            "id": "DOPPLER-001",
                            "name": "Doppler account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOPPLER-002",
                            "name": "Doppler account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOPPLER-003",
                            "name": "Doppler account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOPPLER-004",
                            "name": "Doppler account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="doppler",
                source_type=SourceType.IAM,
                provider="doppler",
                event_type="doppler_activity",
                raw_data={
                    "response": [
                        {
                            "id": "DOPPLER-001",
                            "name": "Doppler account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOPPLER-002",
                            "name": "Doppler account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOPPLER-003",
                            "name": "Doppler account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOPPLER-004",
                            "name": "Doppler account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Infisical
# ---------------------------------------------------------------------------
class DemoInfisicalConnector(BaseConnector):
    """Simulates Infisical collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="infisical",
            source_type=SourceType.IAM,
            provider="infisical",
        )

        result.events.append(
            RawEventData(
                source="infisical",
                source_type=SourceType.IAM,
                provider="infisical",
                event_type="infisical_workspaces",
                raw_data={
                    "response": [
                        {
                            "id": "INFISICAL-001",
                            "name": "Infisical account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INFISICAL-002",
                            "name": "Infisical account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INFISICAL-003",
                            "name": "Infisical account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INFISICAL-004",
                            "name": "Infisical account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="infisical",
                source_type=SourceType.IAM,
                provider="infisical",
                event_type="infisical_secrets",
                raw_data={
                    "response": [
                        {
                            "id": "INFISICAL-001",
                            "name": "Infisical account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INFISICAL-002",
                            "name": "Infisical account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INFISICAL-003",
                            "name": "Infisical account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INFISICAL-004",
                            "name": "Infisical account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="infisical",
                source_type=SourceType.IAM,
                provider="infisical",
                event_type="infisical_audit_logs",
                raw_data={
                    "response": [
                        {
                            "id": "INFISICAL-001",
                            "name": "Infisical account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INFISICAL-002",
                            "name": "Infisical account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INFISICAL-003",
                            "name": "Infisical account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INFISICAL-004",
                            "name": "Infisical account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Bitbucket
# ---------------------------------------------------------------------------
class DemoBitbucketConnector(BaseConnector):
    """Simulates Bitbucket collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="bitbucket",
            source_type=SourceType.CODE,
            provider="bitbucket",
        )

        result.events.append(
            RawEventData(
                source="bitbucket",
                source_type=SourceType.CODE,
                provider="bitbucket",
                event_type="bitbucket_repos",
                raw_data={
                    "response": [
                        {
                            "id": "BITBUCKET-001",
                            "name": "Bitbucket repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BITBUCKET-002",
                            "name": "Bitbucket repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BITBUCKET-003",
                            "name": "Bitbucket repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="bitbucket",
                source_type=SourceType.CODE,
                provider="bitbucket",
                event_type="bitbucket_branch_protections",
                raw_data={
                    "response": [
                        {
                            "id": "BITBUCKET-001",
                            "name": "Bitbucket repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BITBUCKET-002",
                            "name": "Bitbucket repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BITBUCKET-003",
                            "name": "Bitbucket repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BITBUCKET-004",
                            "name": "Bitbucket repo 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="bitbucket",
                source_type=SourceType.CODE,
                provider="bitbucket",
                event_type="bitbucket_commits",
                raw_data={
                    "response": [
                        {
                            "id": "BITBUCKET-001",
                            "name": "Bitbucket repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BITBUCKET-002",
                            "name": "Bitbucket repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BITBUCKET-003",
                            "name": "Bitbucket repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# AWS CodeCommit
# ---------------------------------------------------------------------------
class DemoAWSCodeCommitConnector(BaseConnector):
    """Simulates AWS CodeCommit collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_codecommit",
            source_type=SourceType.CODE,
            provider="aws_codecommit",
        )

        result.events.append(
            RawEventData(
                source="aws_codecommit",
                source_type=SourceType.CODE,
                provider="aws_codecommit",
                event_type="codecommit_repos",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_CODECOMMIT-001",
                            "name": "AWS CodeCommit repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_CODECOMMIT-002",
                            "name": "AWS CodeCommit repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_CODECOMMIT-003",
                            "name": "AWS CodeCommit repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aws_codecommit",
                source_type=SourceType.CODE,
                provider="aws_codecommit",
                event_type="codecommit_approval_rules",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_CODECOMMIT-001",
                            "name": "AWS CodeCommit repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_CODECOMMIT-002",
                            "name": "AWS CodeCommit repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_CODECOMMIT-003",
                            "name": "AWS CodeCommit repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AWS_CODECOMMIT-004",
                            "name": "AWS CodeCommit repo 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Azure Repos
# ---------------------------------------------------------------------------
class DemoAzureReposConnector(BaseConnector):
    """Simulates Azure Repos collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="azure_repos",
            source_type=SourceType.CODE,
            provider="azure_repos",
        )

        result.events.append(
            RawEventData(
                source="azure_repos",
                source_type=SourceType.CODE,
                provider="azure_repos",
                event_type="azure_repos",
                raw_data={
                    "response": [
                        {
                            "id": "AZURE_REPOS-001",
                            "name": "Azure Repos repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AZURE_REPOS-002",
                            "name": "Azure Repos repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AZURE_REPOS-003",
                            "name": "Azure Repos repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="azure_repos",
                source_type=SourceType.CODE,
                provider="azure_repos",
                event_type="azure_pull_requests",
                raw_data={
                    "response": [
                        {
                            "id": "AZURE_REPOS-001",
                            "name": "Azure Repos repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AZURE_REPOS-002",
                            "name": "Azure Repos repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AZURE_REPOS-003",
                            "name": "Azure Repos repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AZURE_REPOS-004",
                            "name": "Azure Repos repo 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="azure_repos",
                source_type=SourceType.CODE,
                provider="azure_repos",
                event_type="azure_branch_policies",
                raw_data={
                    "response": [
                        {
                            "id": "AZURE_REPOS-001",
                            "name": "Azure Repos repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AZURE_REPOS-002",
                            "name": "Azure Repos repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AZURE_REPOS-003",
                            "name": "Azure Repos repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Azure DevOps
# ---------------------------------------------------------------------------
class DemoAzureDevOpsConnector(BaseConnector):
    """Simulates Azure DevOps collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="azure_devops",
            source_type=SourceType.CI_CD,
            provider="azure_devops",
        )

        result.events.append(
            RawEventData(
                source="azure_devops",
                source_type=SourceType.CI_CD,
                provider="azure_devops",
                event_type="azdo_builds",
                raw_data={
                    "response": [
                        {
                            "id": "AZURE_DEVOPS-001",
                            "name": "Azure DevOps pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AZURE_DEVOPS-002",
                            "name": "Azure DevOps pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AZURE_DEVOPS-003",
                            "name": "Azure DevOps pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AZURE_DEVOPS-004",
                            "name": "Azure DevOps pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="azure_devops",
                source_type=SourceType.CI_CD,
                provider="azure_devops",
                event_type="azdo_releases",
                raw_data={
                    "response": [
                        {
                            "id": "AZURE_DEVOPS-001",
                            "name": "Azure DevOps pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AZURE_DEVOPS-002",
                            "name": "Azure DevOps pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AZURE_DEVOPS-003",
                            "name": "Azure DevOps pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AZURE_DEVOPS-004",
                            "name": "Azure DevOps pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="azure_devops",
                source_type=SourceType.CI_CD,
                provider="azure_devops",
                event_type="azdo_work_items",
                raw_data={
                    "response": [
                        {
                            "id": "AZURE_DEVOPS-001",
                            "name": "Azure DevOps pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AZURE_DEVOPS-002",
                            "name": "Azure DevOps pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AZURE_DEVOPS-003",
                            "name": "Azure DevOps pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AZURE_DEVOPS-004",
                            "name": "Azure DevOps pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Argo CD
# ---------------------------------------------------------------------------
class DemoArgoCDConnector(BaseConnector):
    """Simulates Argo CD collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="argocd",
            source_type=SourceType.CI_CD,
            provider="argocd",
        )

        result.events.append(
            RawEventData(
                source="argocd",
                source_type=SourceType.CI_CD,
                provider="argocd",
                event_type="argocd_applications",
                raw_data={
                    "response": [
                        {
                            "id": "ARGOCD-001",
                            "name": "Argo CD pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ARGOCD-002",
                            "name": "Argo CD pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ARGOCD-003",
                            "name": "Argo CD pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ARGOCD-004",
                            "name": "Argo CD pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="argocd",
                source_type=SourceType.CI_CD,
                provider="argocd",
                event_type="argocd_clusters",
                raw_data={
                    "response": [
                        {
                            "id": "ARGOCD-001",
                            "name": "Argo CD pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ARGOCD-002",
                            "name": "Argo CD pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ARGOCD-003",
                            "name": "Argo CD pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ARGOCD-004",
                            "name": "Argo CD pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="argocd",
                source_type=SourceType.CI_CD,
                provider="argocd",
                event_type="argocd_repositories",
                raw_data={
                    "response": [
                        {
                            "id": "ARGOCD-001",
                            "name": "Argo CD pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ARGOCD-002",
                            "name": "Argo CD pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ARGOCD-003",
                            "name": "Argo CD pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ARGOCD-004",
                            "name": "Argo CD pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
class DemoHarnessConnector(BaseConnector):
    """Simulates Harness collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="harness",
            source_type=SourceType.CI_CD,
            provider="harness",
        )

        result.events.append(
            RawEventData(
                source="harness",
                source_type=SourceType.CI_CD,
                provider="harness",
                event_type="harness_pipelines",
                raw_data={
                    "response": [
                        {
                            "id": "HARNESS-001",
                            "name": "Harness pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HARNESS-002",
                            "name": "Harness pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HARNESS-003",
                            "name": "Harness pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HARNESS-004",
                            "name": "Harness pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="harness",
                source_type=SourceType.CI_CD,
                provider="harness",
                event_type="harness_executions",
                raw_data={
                    "response": [
                        {
                            "id": "HARNESS-001",
                            "name": "Harness pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HARNESS-002",
                            "name": "Harness pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HARNESS-003",
                            "name": "Harness pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HARNESS-004",
                            "name": "Harness pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="harness",
                source_type=SourceType.CI_CD,
                provider="harness",
                event_type="harness_connectors",
                raw_data={
                    "response": [
                        {
                            "id": "HARNESS-001",
                            "name": "Harness pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HARNESS-002",
                            "name": "Harness pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HARNESS-003",
                            "name": "Harness pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HARNESS-004",
                            "name": "Harness pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Buildkite
# ---------------------------------------------------------------------------
class DemoBuildkiteConnector(BaseConnector):
    """Simulates Buildkite collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="buildkite",
            source_type=SourceType.CI_CD,
            provider="buildkite",
        )

        result.events.append(
            RawEventData(
                source="buildkite",
                source_type=SourceType.CI_CD,
                provider="buildkite",
                event_type="buildkite_pipelines",
                raw_data={
                    "response": [
                        {
                            "id": "BUILDKITE-001",
                            "name": "Buildkite pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BUILDKITE-002",
                            "name": "Buildkite pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BUILDKITE-003",
                            "name": "Buildkite pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BUILDKITE-004",
                            "name": "Buildkite pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="buildkite",
                source_type=SourceType.CI_CD,
                provider="buildkite",
                event_type="buildkite_builds",
                raw_data={
                    "response": [
                        {
                            "id": "BUILDKITE-001",
                            "name": "Buildkite pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BUILDKITE-002",
                            "name": "Buildkite pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BUILDKITE-003",
                            "name": "Buildkite pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BUILDKITE-004",
                            "name": "Buildkite pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# LaunchDarkly
# ---------------------------------------------------------------------------
class DemoLaunchDarklyConnector(BaseConnector):
    """Simulates LaunchDarkly collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="launchdarkly",
            source_type=SourceType.CI_CD,
            provider="launchdarkly",
        )

        result.events.append(
            RawEventData(
                source="launchdarkly",
                source_type=SourceType.CI_CD,
                provider="launchdarkly",
                event_type="launchdarkly_flags",
                raw_data={
                    "response": [
                        {
                            "id": "LAUNCHDARKLY-001",
                            "name": "LaunchDarkly pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LAUNCHDARKLY-002",
                            "name": "LaunchDarkly pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LAUNCHDARKLY-003",
                            "name": "LaunchDarkly pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LAUNCHDARKLY-004",
                            "name": "LaunchDarkly pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="launchdarkly",
                source_type=SourceType.CI_CD,
                provider="launchdarkly",
                event_type="launchdarkly_audit_log",
                raw_data={
                    "response": [
                        {
                            "id": "LAUNCHDARKLY-001",
                            "name": "LaunchDarkly pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LAUNCHDARKLY-002",
                            "name": "LaunchDarkly pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LAUNCHDARKLY-003",
                            "name": "LaunchDarkly pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LAUNCHDARKLY-004",
                            "name": "LaunchDarkly pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="launchdarkly",
                source_type=SourceType.CI_CD,
                provider="launchdarkly",
                event_type="launchdarkly_members",
                raw_data={
                    "response": [
                        {
                            "id": "LAUNCHDARKLY-001",
                            "name": "LaunchDarkly pipeline 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LAUNCHDARKLY-002",
                            "name": "LaunchDarkly pipeline 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LAUNCHDARKLY-003",
                            "name": "LaunchDarkly pipeline 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LAUNCHDARKLY-004",
                            "name": "LaunchDarkly pipeline 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Fivetran
# ---------------------------------------------------------------------------
class DemoFivetranConnector(BaseConnector):
    """Simulates Fivetran collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="fivetran",
            source_type=SourceType.INFRASTRUCTURE,
            provider="fivetran",
        )

        result.events.append(
            RawEventData(
                source="fivetran",
                source_type=SourceType.INFRASTRUCTURE,
                provider="fivetran",
                event_type="fivetran_connectors",
                raw_data={
                    "response": [
                        {
                            "id": "FIVETRAN-001",
                            "name": "Fivetran resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIVETRAN-002",
                            "name": "Fivetran resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIVETRAN-003",
                            "name": "Fivetran resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FIVETRAN-004",
                            "name": "Fivetran resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fivetran",
                source_type=SourceType.INFRASTRUCTURE,
                provider="fivetran",
                event_type="fivetran_groups",
                raw_data={
                    "response": [
                        {
                            "id": "FIVETRAN-001",
                            "name": "Fivetran resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIVETRAN-002",
                            "name": "Fivetran resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIVETRAN-003",
                            "name": "Fivetran resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FIVETRAN-004",
                            "name": "Fivetran resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fivetran",
                source_type=SourceType.INFRASTRUCTURE,
                provider="fivetran",
                event_type="fivetran_users",
                raw_data={
                    "response": [
                        {
                            "id": "FIVETRAN-001",
                            "name": "Fivetran resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIVETRAN-002",
                            "name": "Fivetran resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIVETRAN-003",
                            "name": "Fivetran resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FIVETRAN-004",
                            "name": "Fivetran resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# dbt Labs
# ---------------------------------------------------------------------------
class DemoDbtLabsConnector(BaseConnector):
    """Simulates dbt Labs collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="dbt_labs",
            source_type=SourceType.INFRASTRUCTURE,
            provider="dbt_labs",
        )

        result.events.append(
            RawEventData(
                source="dbt_labs",
                source_type=SourceType.INFRASTRUCTURE,
                provider="dbt_labs",
                event_type="dbt_projects",
                raw_data={
                    "response": [
                        {
                            "id": "DBT_LABS-001",
                            "name": "dbt Labs resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DBT_LABS-002",
                            "name": "dbt Labs resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DBT_LABS-003",
                            "name": "dbt Labs resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DBT_LABS-004",
                            "name": "dbt Labs resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dbt_labs",
                source_type=SourceType.INFRASTRUCTURE,
                provider="dbt_labs",
                event_type="dbt_runs",
                raw_data={
                    "response": [
                        {
                            "id": "DBT_LABS-001",
                            "name": "dbt Labs resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DBT_LABS-002",
                            "name": "dbt Labs resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DBT_LABS-003",
                            "name": "dbt Labs resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DBT_LABS-004",
                            "name": "dbt Labs resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dbt_labs",
                source_type=SourceType.INFRASTRUCTURE,
                provider="dbt_labs",
                event_type="dbt_environments",
                raw_data={
                    "response": [
                        {
                            "id": "DBT_LABS-001",
                            "name": "dbt Labs resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DBT_LABS-002",
                            "name": "dbt Labs resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DBT_LABS-003",
                            "name": "dbt Labs resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DBT_LABS-004",
                            "name": "dbt Labs resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Asana
# ---------------------------------------------------------------------------
class DemoAsanaConnector(BaseConnector):
    """Simulates Asana collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="asana",
            source_type=SourceType.PROJECT_MGMT,
            provider="asana",
        )

        result.events.append(
            RawEventData(
                source="asana",
                source_type=SourceType.PROJECT_MGMT,
                provider="asana",
                event_type="asana_projects",
                raw_data={
                    "response": [
                        {
                            "id": "ASANA-001",
                            "name": "Asana project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ASANA-002",
                            "name": "Asana project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ASANA-003",
                            "name": "Asana project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ASANA-004",
                            "name": "Asana project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="asana",
                source_type=SourceType.PROJECT_MGMT,
                provider="asana",
                event_type="asana_tasks",
                raw_data={
                    "response": [
                        {
                            "id": "ASANA-001",
                            "name": "Asana project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ASANA-002",
                            "name": "Asana project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ASANA-003",
                            "name": "Asana project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ASANA-004",
                            "name": "Asana project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="asana",
                source_type=SourceType.PROJECT_MGMT,
                provider="asana",
                event_type="asana_users",
                raw_data={
                    "response": [
                        {
                            "id": "ASANA-001",
                            "name": "Asana project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ASANA-002",
                            "name": "Asana project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ASANA-003",
                            "name": "Asana project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ASANA-004",
                            "name": "Asana project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Linear
# ---------------------------------------------------------------------------
class DemoLinearConnector(BaseConnector):
    """Simulates Linear collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="linear",
            source_type=SourceType.PROJECT_MGMT,
            provider="linear",
        )

        result.events.append(
            RawEventData(
                source="linear",
                source_type=SourceType.PROJECT_MGMT,
                provider="linear",
                event_type="linear_issues",
                raw_data={
                    "response": [
                        {
                            "id": "LINEAR-001",
                            "name": "Linear project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LINEAR-002",
                            "name": "Linear project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LINEAR-003",
                            "name": "Linear project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LINEAR-004",
                            "name": "Linear project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="linear",
                source_type=SourceType.PROJECT_MGMT,
                provider="linear",
                event_type="linear_teams",
                raw_data={
                    "response": [
                        {
                            "id": "LINEAR-001",
                            "name": "Linear project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LINEAR-002",
                            "name": "Linear project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LINEAR-003",
                            "name": "Linear project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LINEAR-004",
                            "name": "Linear project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="linear",
                source_type=SourceType.PROJECT_MGMT,
                provider="linear",
                event_type="linear_users",
                raw_data={
                    "response": [
                        {
                            "id": "LINEAR-001",
                            "name": "Linear project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LINEAR-002",
                            "name": "Linear project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LINEAR-003",
                            "name": "Linear project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LINEAR-004",
                            "name": "Linear project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# ClickUp
# ---------------------------------------------------------------------------
class DemoClickUpConnector(BaseConnector):
    """Simulates ClickUp collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="clickup",
            source_type=SourceType.PROJECT_MGMT,
            provider="clickup",
        )

        result.events.append(
            RawEventData(
                source="clickup",
                source_type=SourceType.PROJECT_MGMT,
                provider="clickup",
                event_type="clickup_teams",
                raw_data={
                    "response": [
                        {
                            "id": "CLICKUP-001",
                            "name": "ClickUp project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CLICKUP-002",
                            "name": "ClickUp project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CLICKUP-003",
                            "name": "ClickUp project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CLICKUP-004",
                            "name": "ClickUp project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="clickup",
                source_type=SourceType.PROJECT_MGMT,
                provider="clickup",
                event_type="clickup_spaces",
                raw_data={
                    "response": [
                        {
                            "id": "CLICKUP-001",
                            "name": "ClickUp project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CLICKUP-002",
                            "name": "ClickUp project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CLICKUP-003",
                            "name": "ClickUp project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CLICKUP-004",
                            "name": "ClickUp project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="clickup",
                source_type=SourceType.PROJECT_MGMT,
                provider="clickup",
                event_type="clickup_tasks",
                raw_data={
                    "response": [
                        {
                            "id": "CLICKUP-001",
                            "name": "ClickUp project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CLICKUP-002",
                            "name": "ClickUp project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CLICKUP-003",
                            "name": "ClickUp project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CLICKUP-004",
                            "name": "ClickUp project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Trello
# ---------------------------------------------------------------------------
class DemoTrelloConnector(BaseConnector):
    """Simulates Trello collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="trello",
            source_type=SourceType.PROJECT_MGMT,
            provider="trello",
        )

        result.events.append(
            RawEventData(
                source="trello",
                source_type=SourceType.PROJECT_MGMT,
                provider="trello",
                event_type="trello_boards",
                raw_data={
                    "response": [
                        {
                            "id": "TRELLO-001",
                            "name": "Trello project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRELLO-002",
                            "name": "Trello project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRELLO-003",
                            "name": "Trello project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TRELLO-004",
                            "name": "Trello project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="trello",
                source_type=SourceType.PROJECT_MGMT,
                provider="trello",
                event_type="trello_cards",
                raw_data={
                    "response": [
                        {
                            "id": "TRELLO-001",
                            "name": "Trello project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRELLO-002",
                            "name": "Trello project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRELLO-003",
                            "name": "Trello project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TRELLO-004",
                            "name": "Trello project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Monday.com
# ---------------------------------------------------------------------------
class DemoMondayConnector(BaseConnector):
    """Simulates Monday.com collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="monday",
            source_type=SourceType.PROJECT_MGMT,
            provider="monday",
        )

        result.events.append(
            RawEventData(
                source="monday",
                source_type=SourceType.PROJECT_MGMT,
                provider="monday",
                event_type="monday_boards",
                raw_data={
                    "response": [
                        {
                            "id": "MONDAY-001",
                            "name": "Monday.com project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MONDAY-002",
                            "name": "Monday.com project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MONDAY-003",
                            "name": "Monday.com project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MONDAY-004",
                            "name": "Monday.com project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="monday",
                source_type=SourceType.PROJECT_MGMT,
                provider="monday",
                event_type="monday_items",
                raw_data={
                    "response": [
                        {
                            "id": "MONDAY-001",
                            "name": "Monday.com project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MONDAY-002",
                            "name": "Monday.com project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MONDAY-003",
                            "name": "Monday.com project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MONDAY-004",
                            "name": "Monday.com project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="monday",
                source_type=SourceType.PROJECT_MGMT,
                provider="monday",
                event_type="monday_users",
                raw_data={
                    "response": [
                        {
                            "id": "MONDAY-001",
                            "name": "Monday.com project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MONDAY-002",
                            "name": "Monday.com project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MONDAY-003",
                            "name": "Monday.com project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MONDAY-004",
                            "name": "Monday.com project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Shortcut
# ---------------------------------------------------------------------------
class DemoShortcutConnector(BaseConnector):
    """Simulates Shortcut collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="shortcut",
            source_type=SourceType.PROJECT_MGMT,
            provider="shortcut",
        )

        result.events.append(
            RawEventData(
                source="shortcut",
                source_type=SourceType.PROJECT_MGMT,
                provider="shortcut",
                event_type="shortcut_stories",
                raw_data={
                    "response": [
                        {
                            "id": "SHORTCUT-001",
                            "name": "Shortcut project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SHORTCUT-002",
                            "name": "Shortcut project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SHORTCUT-003",
                            "name": "Shortcut project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SHORTCUT-004",
                            "name": "Shortcut project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="shortcut",
                source_type=SourceType.PROJECT_MGMT,
                provider="shortcut",
                event_type="shortcut_projects",
                raw_data={
                    "response": [
                        {
                            "id": "SHORTCUT-001",
                            "name": "Shortcut project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SHORTCUT-002",
                            "name": "Shortcut project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SHORTCUT-003",
                            "name": "Shortcut project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SHORTCUT-004",
                            "name": "Shortcut project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Notion
# ---------------------------------------------------------------------------
class DemoNotionConnector(BaseConnector):
    """Simulates Notion collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="notion",
            source_type=SourceType.PROJECT_MGMT,
            provider="notion",
        )

        result.events.append(
            RawEventData(
                source="notion",
                source_type=SourceType.PROJECT_MGMT,
                provider="notion",
                event_type="notion_databases",
                raw_data={
                    "response": [
                        {
                            "id": "NOTION-001",
                            "name": "Notion project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NOTION-002",
                            "name": "Notion project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NOTION-003",
                            "name": "Notion project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NOTION-004",
                            "name": "Notion project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="notion",
                source_type=SourceType.PROJECT_MGMT,
                provider="notion",
                event_type="notion_pages",
                raw_data={
                    "response": [
                        {
                            "id": "NOTION-001",
                            "name": "Notion project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NOTION-002",
                            "name": "Notion project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NOTION-003",
                            "name": "Notion project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NOTION-004",
                            "name": "Notion project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="notion",
                source_type=SourceType.PROJECT_MGMT,
                provider="notion",
                event_type="notion_users",
                raw_data={
                    "response": [
                        {
                            "id": "NOTION-001",
                            "name": "Notion project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NOTION-002",
                            "name": "Notion project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NOTION-003",
                            "name": "Notion project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NOTION-004",
                            "name": "Notion project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Smartsheet
# ---------------------------------------------------------------------------
class DemoSmartsheetConnector(BaseConnector):
    """Simulates Smartsheet collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="smartsheet",
            source_type=SourceType.PROJECT_MGMT,
            provider="smartsheet",
        )

        result.events.append(
            RawEventData(
                source="smartsheet",
                source_type=SourceType.PROJECT_MGMT,
                provider="smartsheet",
                event_type="smartsheet_sheets",
                raw_data={
                    "response": [
                        {
                            "id": "SMARTSHEET-001",
                            "name": "Smartsheet project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SMARTSHEET-002",
                            "name": "Smartsheet project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SMARTSHEET-003",
                            "name": "Smartsheet project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SMARTSHEET-004",
                            "name": "Smartsheet project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="smartsheet",
                source_type=SourceType.PROJECT_MGMT,
                provider="smartsheet",
                event_type="smartsheet_users",
                raw_data={
                    "response": [
                        {
                            "id": "SMARTSHEET-001",
                            "name": "Smartsheet project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SMARTSHEET-002",
                            "name": "Smartsheet project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SMARTSHEET-003",
                            "name": "Smartsheet project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SMARTSHEET-004",
                            "name": "Smartsheet project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="smartsheet",
                source_type=SourceType.PROJECT_MGMT,
                provider="smartsheet",
                event_type="smartsheet_reports",
                raw_data={
                    "response": [
                        {
                            "id": "SMARTSHEET-001",
                            "name": "Smartsheet project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SMARTSHEET-002",
                            "name": "Smartsheet project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SMARTSHEET-003",
                            "name": "Smartsheet project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SMARTSHEET-004",
                            "name": "Smartsheet project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Wrike
# ---------------------------------------------------------------------------
class DemoWrikeConnector(BaseConnector):
    """Simulates Wrike collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="wrike",
            source_type=SourceType.PROJECT_MGMT,
            provider="wrike",
        )

        result.events.append(
            RawEventData(
                source="wrike",
                source_type=SourceType.PROJECT_MGMT,
                provider="wrike",
                event_type="wrike_folders",
                raw_data={
                    "response": [
                        {
                            "id": "WRIKE-001",
                            "name": "Wrike project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WRIKE-002",
                            "name": "Wrike project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WRIKE-003",
                            "name": "Wrike project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WRIKE-004",
                            "name": "Wrike project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="wrike",
                source_type=SourceType.PROJECT_MGMT,
                provider="wrike",
                event_type="wrike_tasks",
                raw_data={
                    "response": [
                        {
                            "id": "WRIKE-001",
                            "name": "Wrike project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WRIKE-002",
                            "name": "Wrike project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WRIKE-003",
                            "name": "Wrike project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WRIKE-004",
                            "name": "Wrike project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="wrike",
                source_type=SourceType.PROJECT_MGMT,
                provider="wrike",
                event_type="wrike_contacts",
                raw_data={
                    "response": [
                        {
                            "id": "WRIKE-001",
                            "name": "Wrike project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WRIKE-002",
                            "name": "Wrike project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WRIKE-003",
                            "name": "Wrike project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WRIKE-004",
                            "name": "Wrike project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Basecamp
# ---------------------------------------------------------------------------
class DemoBasecampConnector(BaseConnector):
    """Simulates Basecamp collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="basecamp",
            source_type=SourceType.PROJECT_MGMT,
            provider="basecamp",
        )

        result.events.append(
            RawEventData(
                source="basecamp",
                source_type=SourceType.PROJECT_MGMT,
                provider="basecamp",
                event_type="basecamp_projects",
                raw_data={
                    "response": [
                        {
                            "id": "BASECAMP-001",
                            "name": "Basecamp project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BASECAMP-002",
                            "name": "Basecamp project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BASECAMP-003",
                            "name": "Basecamp project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BASECAMP-004",
                            "name": "Basecamp project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="basecamp",
                source_type=SourceType.PROJECT_MGMT,
                provider="basecamp",
                event_type="basecamp_people",
                raw_data={
                    "response": [
                        {
                            "id": "BASECAMP-001",
                            "name": "Basecamp project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BASECAMP-002",
                            "name": "Basecamp project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BASECAMP-003",
                            "name": "Basecamp project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BASECAMP-004",
                            "name": "Basecamp project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Height
# ---------------------------------------------------------------------------
class DemoHeightConnector(BaseConnector):
    """Simulates Height collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="height",
            source_type=SourceType.PROJECT_MGMT,
            provider="height",
        )

        result.events.append(
            RawEventData(
                source="height",
                source_type=SourceType.PROJECT_MGMT,
                provider="height",
                event_type="height_lists",
                raw_data={
                    "response": [
                        {
                            "id": "HEIGHT-001",
                            "name": "Height project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HEIGHT-002",
                            "name": "Height project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HEIGHT-003",
                            "name": "Height project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HEIGHT-004",
                            "name": "Height project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="height",
                source_type=SourceType.PROJECT_MGMT,
                provider="height",
                event_type="height_tasks",
                raw_data={
                    "response": [
                        {
                            "id": "HEIGHT-001",
                            "name": "Height project 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HEIGHT-002",
                            "name": "Height project 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HEIGHT-003",
                            "name": "Height project 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HEIGHT-004",
                            "name": "Height project 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Freshservice
# ---------------------------------------------------------------------------
class DemoFreshserviceConnector(BaseConnector):
    """Simulates Freshservice collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="freshservice",
            source_type=SourceType.ITSM,
            provider="freshservice",
        )

        result.events.append(
            RawEventData(
                source="freshservice",
                source_type=SourceType.ITSM,
                provider="freshservice",
                event_type="freshservice_tickets",
                raw_data={
                    "response": [
                        {
                            "id": "FRESHSERVICE-001",
                            "name": "Freshservice ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FRESHSERVICE-002",
                            "name": "Freshservice ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FRESHSERVICE-003",
                            "name": "Freshservice ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="freshservice",
                source_type=SourceType.ITSM,
                provider="freshservice",
                event_type="freshservice_assets",
                raw_data={
                    "response": [
                        {
                            "id": "FRESHSERVICE-001",
                            "name": "Freshservice ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FRESHSERVICE-002",
                            "name": "Freshservice ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FRESHSERVICE-003",
                            "name": "Freshservice ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FRESHSERVICE-004",
                            "name": "Freshservice ticket 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="freshservice",
                source_type=SourceType.ITSM,
                provider="freshservice",
                event_type="freshservice_changes",
                raw_data={
                    "response": [
                        {
                            "id": "FRESHSERVICE-001",
                            "name": "Freshservice ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FRESHSERVICE-002",
                            "name": "Freshservice ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FRESHSERVICE-003",
                            "name": "Freshservice ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Freshdesk
# ---------------------------------------------------------------------------
class DemoFreshdeskConnector(BaseConnector):
    """Simulates Freshdesk collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="freshdesk",
            source_type=SourceType.ITSM,
            provider="freshdesk",
        )

        result.events.append(
            RawEventData(
                source="freshdesk",
                source_type=SourceType.ITSM,
                provider="freshdesk",
                event_type="freshdesk_tickets",
                raw_data={
                    "response": [
                        {
                            "id": "FRESHDESK-001",
                            "name": "Freshdesk ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FRESHDESK-002",
                            "name": "Freshdesk ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FRESHDESK-003",
                            "name": "Freshdesk ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="freshdesk",
                source_type=SourceType.ITSM,
                provider="freshdesk",
                event_type="freshdesk_agents",
                raw_data={
                    "response": [
                        {
                            "id": "FRESHDESK-001",
                            "name": "Freshdesk ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FRESHDESK-002",
                            "name": "Freshdesk ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FRESHDESK-003",
                            "name": "Freshdesk ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FRESHDESK-004",
                            "name": "Freshdesk ticket 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="freshdesk",
                source_type=SourceType.ITSM,
                provider="freshdesk",
                event_type="freshdesk_contacts",
                raw_data={
                    "response": [
                        {
                            "id": "FRESHDESK-001",
                            "name": "Freshdesk ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FRESHDESK-002",
                            "name": "Freshdesk ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FRESHDESK-003",
                            "name": "Freshdesk ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Zendesk
# ---------------------------------------------------------------------------
class DemoZendeskConnector(BaseConnector):
    """Simulates Zendesk collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="zendesk",
            source_type=SourceType.ITSM,
            provider="zendesk",
        )

        result.events.append(
            RawEventData(
                source="zendesk",
                source_type=SourceType.ITSM,
                provider="zendesk",
                event_type="zendesk_tickets",
                raw_data={
                    "response": [
                        {
                            "id": "ZENDESK-001",
                            "name": "Zendesk ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZENDESK-002",
                            "name": "Zendesk ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZENDESK-003",
                            "name": "Zendesk ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="zendesk",
                source_type=SourceType.ITSM,
                provider="zendesk",
                event_type="zendesk_users",
                raw_data={
                    "response": [
                        {
                            "id": "ZENDESK-001",
                            "name": "Zendesk ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZENDESK-002",
                            "name": "Zendesk ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZENDESK-003",
                            "name": "Zendesk ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ZENDESK-004",
                            "name": "Zendesk ticket 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="zendesk",
                source_type=SourceType.ITSM,
                provider="zendesk",
                event_type="zendesk_audit_logs",
                raw_data={
                    "response": [
                        {
                            "id": "ZENDESK-001",
                            "name": "Zendesk ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZENDESK-002",
                            "name": "Zendesk ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZENDESK-003",
                            "name": "Zendesk ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Zoho Desk
# ---------------------------------------------------------------------------
class DemoZohoDeskConnector(BaseConnector):
    """Simulates Zoho Desk collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="zoho_desk",
            source_type=SourceType.ITSM,
            provider="zoho_desk",
        )

        result.events.append(
            RawEventData(
                source="zoho_desk",
                source_type=SourceType.ITSM,
                provider="zoho_desk",
                event_type="zoho_desk_tickets",
                raw_data={
                    "response": [
                        {
                            "id": "ZOHO_DESK-001",
                            "name": "Zoho Desk ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZOHO_DESK-002",
                            "name": "Zoho Desk ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZOHO_DESK-003",
                            "name": "Zoho Desk ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="zoho_desk",
                source_type=SourceType.ITSM,
                provider="zoho_desk",
                event_type="zoho_desk_agents",
                raw_data={
                    "response": [
                        {
                            "id": "ZOHO_DESK-001",
                            "name": "Zoho Desk ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZOHO_DESK-002",
                            "name": "Zoho Desk ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZOHO_DESK-003",
                            "name": "Zoho Desk ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ZOHO_DESK-004",
                            "name": "Zoho Desk ticket 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="zoho_desk",
                source_type=SourceType.ITSM,
                provider="zoho_desk",
                event_type="zoho_desk_departments",
                raw_data={
                    "response": [
                        {
                            "id": "ZOHO_DESK-001",
                            "name": "Zoho Desk ticket 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZOHO_DESK-002",
                            "name": "Zoho Desk ticket 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZOHO_DESK-003",
                            "name": "Zoho Desk ticket 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# HiBob
# ---------------------------------------------------------------------------
class DemoHiBobConnector(BaseConnector):
    """Simulates HiBob collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="hibob",
            source_type=SourceType.HRIS,
            provider="hibob",
        )

        result.events.append(
            RawEventData(
                source="hibob",
                source_type=SourceType.HRIS,
                provider="hibob",
                event_type="hibob_employees",
                raw_data={
                    "response": [
                        {
                            "id": "HIBOB-001",
                            "name": "HiBob employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HIBOB-002",
                            "name": "HiBob employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HIBOB-003",
                            "name": "HiBob employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HIBOB-004",
                            "name": "HiBob employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hibob",
                source_type=SourceType.HRIS,
                provider="hibob",
                event_type="hibob_custom_tables",
                raw_data={
                    "response": [
                        {
                            "id": "HIBOB-001",
                            "name": "HiBob employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HIBOB-002",
                            "name": "HiBob employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HIBOB-003",
                            "name": "HiBob employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HIBOB-004",
                            "name": "HiBob employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hibob",
                source_type=SourceType.HRIS,
                provider="hibob",
                event_type="hibob_timeoff",
                raw_data={
                    "response": [
                        {
                            "id": "HIBOB-001",
                            "name": "HiBob employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HIBOB-002",
                            "name": "HiBob employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HIBOB-003",
                            "name": "HiBob employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HIBOB-004",
                            "name": "HiBob employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Justworks
# ---------------------------------------------------------------------------
class DemoJustworksConnector(BaseConnector):
    """Simulates Justworks collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="justworks",
            source_type=SourceType.HRIS,
            provider="justworks",
        )

        result.events.append(
            RawEventData(
                source="justworks",
                source_type=SourceType.HRIS,
                provider="justworks",
                event_type="justworks_employees",
                raw_data={
                    "response": [
                        {
                            "id": "JUSTWORKS-001",
                            "name": "Justworks employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "JUSTWORKS-002",
                            "name": "Justworks employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "JUSTWORKS-003",
                            "name": "Justworks employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "JUSTWORKS-004",
                            "name": "Justworks employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="justworks",
                source_type=SourceType.HRIS,
                provider="justworks",
                event_type="justworks_departments",
                raw_data={
                    "response": [
                        {
                            "id": "JUSTWORKS-001",
                            "name": "Justworks employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "JUSTWORKS-002",
                            "name": "Justworks employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "JUSTWORKS-003",
                            "name": "Justworks employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "JUSTWORKS-004",
                            "name": "Justworks employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Lattice
# ---------------------------------------------------------------------------
class DemoLatticeConnector(BaseConnector):
    """Simulates Lattice collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="lattice",
            source_type=SourceType.HRIS,
            provider="lattice",
        )

        result.events.append(
            RawEventData(
                source="lattice",
                source_type=SourceType.HRIS,
                provider="lattice",
                event_type="lattice_users",
                raw_data={
                    "response": [
                        {
                            "id": "LATTICE-001",
                            "name": "Lattice employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LATTICE-002",
                            "name": "Lattice employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LATTICE-003",
                            "name": "Lattice employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LATTICE-004",
                            "name": "Lattice employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="lattice",
                source_type=SourceType.HRIS,
                provider="lattice",
                event_type="lattice_goals",
                raw_data={
                    "response": [
                        {
                            "id": "LATTICE-001",
                            "name": "Lattice employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LATTICE-002",
                            "name": "Lattice employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LATTICE-003",
                            "name": "Lattice employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LATTICE-004",
                            "name": "Lattice employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="lattice",
                source_type=SourceType.HRIS,
                provider="lattice",
                event_type="lattice_reviews",
                raw_data={
                    "response": [
                        {
                            "id": "LATTICE-001",
                            "name": "Lattice employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LATTICE-002",
                            "name": "Lattice employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LATTICE-003",
                            "name": "Lattice employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LATTICE-004",
                            "name": "Lattice employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# TriNet
# ---------------------------------------------------------------------------
class DemoTriNetConnector(BaseConnector):
    """Simulates TriNet collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="trinet",
            source_type=SourceType.HRIS,
            provider="trinet",
        )

        result.events.append(
            RawEventData(
                source="trinet",
                source_type=SourceType.HRIS,
                provider="trinet",
                event_type="trinet_employees",
                raw_data={
                    "response": [
                        {
                            "id": "TRINET-001",
                            "name": "TriNet employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRINET-002",
                            "name": "TriNet employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRINET-003",
                            "name": "TriNet employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TRINET-004",
                            "name": "TriNet employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="trinet",
                source_type=SourceType.HRIS,
                provider="trinet",
                event_type="trinet_payroll",
                raw_data={
                    "response": [
                        {
                            "id": "TRINET-001",
                            "name": "TriNet employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRINET-002",
                            "name": "TriNet employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRINET-003",
                            "name": "TriNet employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TRINET-004",
                            "name": "TriNet employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Dayforce (Ceridian)
# ---------------------------------------------------------------------------
class DemoDayforceConnector(BaseConnector):
    """Simulates Dayforce (Ceridian) collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="dayforce",
            source_type=SourceType.HRIS,
            provider="dayforce",
        )

        result.events.append(
            RawEventData(
                source="dayforce",
                source_type=SourceType.HRIS,
                provider="dayforce",
                event_type="dayforce_employees",
                raw_data={
                    "response": [
                        {
                            "id": "DAYFORCE-001",
                            "name": "Dayforce (Ceridian) employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DAYFORCE-002",
                            "name": "Dayforce (Ceridian) employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DAYFORCE-003",
                            "name": "Dayforce (Ceridian) employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DAYFORCE-004",
                            "name": "Dayforce (Ceridian) employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dayforce",
                source_type=SourceType.HRIS,
                provider="dayforce",
                event_type="dayforce_departments",
                raw_data={
                    "response": [
                        {
                            "id": "DAYFORCE-001",
                            "name": "Dayforce (Ceridian) employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DAYFORCE-002",
                            "name": "Dayforce (Ceridian) employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DAYFORCE-003",
                            "name": "Dayforce (Ceridian) employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DAYFORCE-004",
                            "name": "Dayforce (Ceridian) employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dayforce",
                source_type=SourceType.HRIS,
                provider="dayforce",
                event_type="dayforce_time",
                raw_data={
                    "response": [
                        {
                            "id": "DAYFORCE-001",
                            "name": "Dayforce (Ceridian) employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DAYFORCE-002",
                            "name": "Dayforce (Ceridian) employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DAYFORCE-003",
                            "name": "Dayforce (Ceridian) employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DAYFORCE-004",
                            "name": "Dayforce (Ceridian) employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Oracle HCM
# ---------------------------------------------------------------------------
class DemoOracleHCMConnector(BaseConnector):
    """Simulates Oracle HCM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="oracle_hcm",
            source_type=SourceType.HRIS,
            provider="oracle_hcm",
        )

        result.events.append(
            RawEventData(
                source="oracle_hcm",
                source_type=SourceType.HRIS,
                provider="oracle_hcm",
                event_type="oracle_hcm_workers",
                raw_data={
                    "response": [
                        {
                            "id": "ORACLE_HCM-001",
                            "name": "Oracle HCM employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ORACLE_HCM-002",
                            "name": "Oracle HCM employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ORACLE_HCM-003",
                            "name": "Oracle HCM employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ORACLE_HCM-004",
                            "name": "Oracle HCM employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="oracle_hcm",
                source_type=SourceType.HRIS,
                provider="oracle_hcm",
                event_type="oracle_hcm_departments",
                raw_data={
                    "response": [
                        {
                            "id": "ORACLE_HCM-001",
                            "name": "Oracle HCM employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ORACLE_HCM-002",
                            "name": "Oracle HCM employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ORACLE_HCM-003",
                            "name": "Oracle HCM employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ORACLE_HCM-004",
                            "name": "Oracle HCM employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="oracle_hcm",
                source_type=SourceType.HRIS,
                provider="oracle_hcm",
                event_type="oracle_hcm_absences",
                raw_data={
                    "response": [
                        {
                            "id": "ORACLE_HCM-001",
                            "name": "Oracle HCM employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ORACLE_HCM-002",
                            "name": "Oracle HCM employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ORACLE_HCM-003",
                            "name": "Oracle HCM employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ORACLE_HCM-004",
                            "name": "Oracle HCM employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Personio
# ---------------------------------------------------------------------------
class DemoPersonioConnector(BaseConnector):
    """Simulates Personio collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="personio",
            source_type=SourceType.HRIS,
            provider="personio",
        )

        result.events.append(
            RawEventData(
                source="personio",
                source_type=SourceType.HRIS,
                provider="personio",
                event_type="personio_employees",
                raw_data={
                    "response": [
                        {
                            "id": "PERSONIO-001",
                            "name": "Personio employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PERSONIO-002",
                            "name": "Personio employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PERSONIO-003",
                            "name": "Personio employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PERSONIO-004",
                            "name": "Personio employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="personio",
                source_type=SourceType.HRIS,
                provider="personio",
                event_type="personio_attendances",
                raw_data={
                    "response": [
                        {
                            "id": "PERSONIO-001",
                            "name": "Personio employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PERSONIO-002",
                            "name": "Personio employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PERSONIO-003",
                            "name": "Personio employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PERSONIO-004",
                            "name": "Personio employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Deel
# ---------------------------------------------------------------------------
class DemoDeelConnector(BaseConnector):
    """Simulates Deel collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="deel",
            source_type=SourceType.HRIS,
            provider="deel",
        )

        result.events.append(
            RawEventData(
                source="deel",
                source_type=SourceType.HRIS,
                provider="deel",
                event_type="deel_contracts",
                raw_data={
                    "response": [
                        {
                            "id": "DEEL-001",
                            "name": "Deel employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DEEL-002",
                            "name": "Deel employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DEEL-003",
                            "name": "Deel employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DEEL-004",
                            "name": "Deel employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="deel",
                source_type=SourceType.HRIS,
                provider="deel",
                event_type="deel_people",
                raw_data={
                    "response": [
                        {
                            "id": "DEEL-001",
                            "name": "Deel employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DEEL-002",
                            "name": "Deel employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DEEL-003",
                            "name": "Deel employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DEEL-004",
                            "name": "Deel employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Namely
# ---------------------------------------------------------------------------
class DemoNamelyConnector(BaseConnector):
    """Simulates Namely collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="namely",
            source_type=SourceType.HRIS,
            provider="namely",
        )

        result.events.append(
            RawEventData(
                source="namely",
                source_type=SourceType.HRIS,
                provider="namely",
                event_type="namely_profiles",
                raw_data={
                    "response": [
                        {
                            "id": "NAMELY-001",
                            "name": "Namely employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NAMELY-002",
                            "name": "Namely employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NAMELY-003",
                            "name": "Namely employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NAMELY-004",
                            "name": "Namely employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="namely",
                source_type=SourceType.HRIS,
                provider="namely",
                event_type="namely_groups",
                raw_data={
                    "response": [
                        {
                            "id": "NAMELY-001",
                            "name": "Namely employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NAMELY-002",
                            "name": "Namely employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NAMELY-003",
                            "name": "Namely employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NAMELY-004",
                            "name": "Namely employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Paychex Flex
# ---------------------------------------------------------------------------
class DemoPaychexFlexConnector(BaseConnector):
    """Simulates Paychex Flex collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="paychex_flex",
            source_type=SourceType.HRIS,
            provider="paychex_flex",
        )

        result.events.append(
            RawEventData(
                source="paychex_flex",
                source_type=SourceType.HRIS,
                provider="paychex_flex",
                event_type="paychex_workers",
                raw_data={
                    "response": [
                        {
                            "id": "PAYCHEX_FLEX-001",
                            "name": "Paychex Flex employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PAYCHEX_FLEX-002",
                            "name": "Paychex Flex employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PAYCHEX_FLEX-003",
                            "name": "Paychex Flex employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PAYCHEX_FLEX-004",
                            "name": "Paychex Flex employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="paychex_flex",
                source_type=SourceType.HRIS,
                provider="paychex_flex",
                event_type="paychex_company_workers",
                raw_data={
                    "response": [
                        {
                            "id": "PAYCHEX_FLEX-001",
                            "name": "Paychex Flex employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PAYCHEX_FLEX-002",
                            "name": "Paychex Flex employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PAYCHEX_FLEX-003",
                            "name": "Paychex Flex employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PAYCHEX_FLEX-004",
                            "name": "Paychex Flex employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Humaans
# ---------------------------------------------------------------------------
class DemoHumaansConnector(BaseConnector):
    """Simulates Humaans collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="humaans",
            source_type=SourceType.HRIS,
            provider="humaans",
        )

        result.events.append(
            RawEventData(
                source="humaans",
                source_type=SourceType.HRIS,
                provider="humaans",
                event_type="humaans_people",
                raw_data={
                    "response": [
                        {
                            "id": "HUMAANS-001",
                            "name": "Humaans employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HUMAANS-002",
                            "name": "Humaans employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HUMAANS-003",
                            "name": "Humaans employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HUMAANS-004",
                            "name": "Humaans employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="humaans",
                source_type=SourceType.HRIS,
                provider="humaans",
                event_type="humaans_time_away",
                raw_data={
                    "response": [
                        {
                            "id": "HUMAANS-001",
                            "name": "Humaans employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HUMAANS-002",
                            "name": "Humaans employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HUMAANS-003",
                            "name": "Humaans employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HUMAANS-004",
                            "name": "Humaans employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Xero (Payroll)
# ---------------------------------------------------------------------------
class DemoXeroPayrollConnector(BaseConnector):
    """Simulates Xero (Payroll) collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="xero_payroll",
            source_type=SourceType.HRIS,
            provider="xero_payroll",
        )

        result.events.append(
            RawEventData(
                source="xero_payroll",
                source_type=SourceType.HRIS,
                provider="xero_payroll",
                event_type="xero_employees",
                raw_data={
                    "response": [
                        {
                            "id": "XERO_PAYROLL-001",
                            "name": "Xero (Payroll) employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "XERO_PAYROLL-002",
                            "name": "Xero (Payroll) employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "XERO_PAYROLL-003",
                            "name": "Xero (Payroll) employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "XERO_PAYROLL-004",
                            "name": "Xero (Payroll) employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="xero_payroll",
                source_type=SourceType.HRIS,
                provider="xero_payroll",
                event_type="xero_pay_runs",
                raw_data={
                    "response": [
                        {
                            "id": "XERO_PAYROLL-001",
                            "name": "Xero (Payroll) employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "XERO_PAYROLL-002",
                            "name": "Xero (Payroll) employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "XERO_PAYROLL-003",
                            "name": "Xero (Payroll) employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "XERO_PAYROLL-004",
                            "name": "Xero (Payroll) employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# 15Five
# ---------------------------------------------------------------------------
class DemoFifteenFiveConnector(BaseConnector):
    """Simulates 15Five collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="fifteenfive",
            source_type=SourceType.HRIS,
            provider="fifteenfive",
        )

        result.events.append(
            RawEventData(
                source="fifteenfive",
                source_type=SourceType.HRIS,
                provider="fifteenfive",
                event_type="fifteenfive_users",
                raw_data={
                    "response": [
                        {
                            "id": "FIFTEENFIVE-001",
                            "name": "15Five employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIFTEENFIVE-002",
                            "name": "15Five employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIFTEENFIVE-003",
                            "name": "15Five employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FIFTEENFIVE-004",
                            "name": "15Five employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fifteenfive",
                source_type=SourceType.HRIS,
                provider="fifteenfive",
                event_type="fifteenfive_reviews",
                raw_data={
                    "response": [
                        {
                            "id": "FIFTEENFIVE-001",
                            "name": "15Five employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIFTEENFIVE-002",
                            "name": "15Five employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIFTEENFIVE-003",
                            "name": "15Five employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FIFTEENFIVE-004",
                            "name": "15Five employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Leapsome
# ---------------------------------------------------------------------------
class DemoLeapsomeConnector(BaseConnector):
    """Simulates Leapsome collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="leapsome",
            source_type=SourceType.HRIS,
            provider="leapsome",
        )

        result.events.append(
            RawEventData(
                source="leapsome",
                source_type=SourceType.HRIS,
                provider="leapsome",
                event_type="leapsome_users",
                raw_data={
                    "response": [
                        {
                            "id": "LEAPSOME-001",
                            "name": "Leapsome employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LEAPSOME-002",
                            "name": "Leapsome employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LEAPSOME-003",
                            "name": "Leapsome employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LEAPSOME-004",
                            "name": "Leapsome employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="leapsome",
                source_type=SourceType.HRIS,
                provider="leapsome",
                event_type="leapsome_reviews",
                raw_data={
                    "response": [
                        {
                            "id": "LEAPSOME-001",
                            "name": "Leapsome employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LEAPSOME-002",
                            "name": "Leapsome employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LEAPSOME-003",
                            "name": "Leapsome employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LEAPSOME-004",
                            "name": "Leapsome employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# HR Cloud
# ---------------------------------------------------------------------------
class DemoHRCloudConnector(BaseConnector):
    """Simulates HR Cloud collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="hr_cloud",
            source_type=SourceType.HRIS,
            provider="hr_cloud",
        )

        result.events.append(
            RawEventData(
                source="hr_cloud",
                source_type=SourceType.HRIS,
                provider="hr_cloud",
                event_type="hrcloud_employees",
                raw_data={
                    "response": [
                        {
                            "id": "HR_CLOUD-001",
                            "name": "HR Cloud employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HR_CLOUD-002",
                            "name": "HR Cloud employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HR_CLOUD-003",
                            "name": "HR Cloud employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HR_CLOUD-004",
                            "name": "HR Cloud employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hr_cloud",
                source_type=SourceType.HRIS,
                provider="hr_cloud",
                event_type="hrcloud_departments",
                raw_data={
                    "response": [
                        {
                            "id": "HR_CLOUD-001",
                            "name": "HR Cloud employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HR_CLOUD-002",
                            "name": "HR Cloud employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HR_CLOUD-003",
                            "name": "HR Cloud employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HR_CLOUD-004",
                            "name": "HR Cloud employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# iSolved
# ---------------------------------------------------------------------------
class DemoISolvedConnector(BaseConnector):
    """Simulates iSolved collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="isolved",
            source_type=SourceType.HRIS,
            provider="isolved",
        )

        result.events.append(
            RawEventData(
                source="isolved",
                source_type=SourceType.HRIS,
                provider="isolved",
                event_type="isolved_employees",
                raw_data={
                    "response": [
                        {
                            "id": "ISOLVED-001",
                            "name": "iSolved employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ISOLVED-002",
                            "name": "iSolved employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ISOLVED-003",
                            "name": "iSolved employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ISOLVED-004",
                            "name": "iSolved employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="isolved",
                source_type=SourceType.HRIS,
                provider="isolved",
                event_type="isolved_payroll",
                raw_data={
                    "response": [
                        {
                            "id": "ISOLVED-001",
                            "name": "iSolved employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ISOLVED-002",
                            "name": "iSolved employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ISOLVED-003",
                            "name": "iSolved employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ISOLVED-004",
                            "name": "iSolved employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Kenjo
# ---------------------------------------------------------------------------
class DemoKenjoConnector(BaseConnector):
    """Simulates Kenjo collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="kenjo",
            source_type=SourceType.HRIS,
            provider="kenjo",
        )

        result.events.append(
            RawEventData(
                source="kenjo",
                source_type=SourceType.HRIS,
                provider="kenjo",
                event_type="kenjo_employees",
                raw_data={
                    "response": [
                        {
                            "id": "KENJO-001",
                            "name": "Kenjo employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KENJO-002",
                            "name": "Kenjo employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KENJO-003",
                            "name": "Kenjo employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KENJO-004",
                            "name": "Kenjo employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="kenjo",
                source_type=SourceType.HRIS,
                provider="kenjo",
                event_type="kenjo_time_off",
                raw_data={
                    "response": [
                        {
                            "id": "KENJO-001",
                            "name": "Kenjo employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KENJO-002",
                            "name": "Kenjo employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KENJO-003",
                            "name": "Kenjo employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KENJO-004",
                            "name": "Kenjo employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Employment Hero
# ---------------------------------------------------------------------------
class DemoEmploymentHeroConnector(BaseConnector):
    """Simulates Employment Hero collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="employment_hero",
            source_type=SourceType.HRIS,
            provider="employment_hero",
        )

        result.events.append(
            RawEventData(
                source="employment_hero",
                source_type=SourceType.HRIS,
                provider="employment_hero",
                event_type="employment_hero_employees",
                raw_data={
                    "response": [
                        {
                            "id": "EMPLOYMENT_HERO-001",
                            "name": "Employment Hero employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EMPLOYMENT_HERO-002",
                            "name": "Employment Hero employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EMPLOYMENT_HERO-003",
                            "name": "Employment Hero employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "EMPLOYMENT_HERO-004",
                            "name": "Employment Hero employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="employment_hero",
                source_type=SourceType.HRIS,
                provider="employment_hero",
                event_type="employment_hero_leave",
                raw_data={
                    "response": [
                        {
                            "id": "EMPLOYMENT_HERO-001",
                            "name": "Employment Hero employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EMPLOYMENT_HERO-002",
                            "name": "Employment Hero employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EMPLOYMENT_HERO-003",
                            "name": "Employment Hero employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "EMPLOYMENT_HERO-004",
                            "name": "Employment Hero employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Zoho People
# ---------------------------------------------------------------------------
class DemoZohoPeopleConnector(BaseConnector):
    """Simulates Zoho People collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="zoho_people",
            source_type=SourceType.HRIS,
            provider="zoho_people",
        )

        result.events.append(
            RawEventData(
                source="zoho_people",
                source_type=SourceType.HRIS,
                provider="zoho_people",
                event_type="zoho_people_employees",
                raw_data={
                    "response": [
                        {
                            "id": "ZOHO_PEOPLE-001",
                            "name": "Zoho People employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZOHO_PEOPLE-002",
                            "name": "Zoho People employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZOHO_PEOPLE-003",
                            "name": "Zoho People employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ZOHO_PEOPLE-004",
                            "name": "Zoho People employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="zoho_people",
                source_type=SourceType.HRIS,
                provider="zoho_people",
                event_type="zoho_people_attendance",
                raw_data={
                    "response": [
                        {
                            "id": "ZOHO_PEOPLE-001",
                            "name": "Zoho People employee 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZOHO_PEOPLE-002",
                            "name": "Zoho People employee 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZOHO_PEOPLE-003",
                            "name": "Zoho People employee 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ZOHO_PEOPLE-004",
                            "name": "Zoho People employee 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Greenhouse
# ---------------------------------------------------------------------------
class DemoGreenhouseConnector(BaseConnector):
    """Simulates Greenhouse collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="greenhouse",
            source_type=SourceType.RECRUITING,
            provider="greenhouse",
        )

        result.events.append(
            RawEventData(
                source="greenhouse",
                source_type=SourceType.RECRUITING,
                provider="greenhouse",
                event_type="greenhouse_candidates",
                raw_data={
                    "response": [
                        {
                            "id": "GREENHOUSE-001",
                            "name": "Greenhouse candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GREENHOUSE-002",
                            "name": "Greenhouse candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GREENHOUSE-003",
                            "name": "Greenhouse candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GREENHOUSE-004",
                            "name": "Greenhouse candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="greenhouse",
                source_type=SourceType.RECRUITING,
                provider="greenhouse",
                event_type="greenhouse_jobs",
                raw_data={
                    "response": [
                        {
                            "id": "GREENHOUSE-001",
                            "name": "Greenhouse candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GREENHOUSE-002",
                            "name": "Greenhouse candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GREENHOUSE-003",
                            "name": "Greenhouse candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GREENHOUSE-004",
                            "name": "Greenhouse candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="greenhouse",
                source_type=SourceType.RECRUITING,
                provider="greenhouse",
                event_type="greenhouse_offers",
                raw_data={
                    "response": [
                        {
                            "id": "GREENHOUSE-001",
                            "name": "Greenhouse candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GREENHOUSE-002",
                            "name": "Greenhouse candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GREENHOUSE-003",
                            "name": "Greenhouse candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GREENHOUSE-004",
                            "name": "Greenhouse candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Lever
# ---------------------------------------------------------------------------
class DemoLeverConnector(BaseConnector):
    """Simulates Lever collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="lever",
            source_type=SourceType.RECRUITING,
            provider="lever",
        )

        result.events.append(
            RawEventData(
                source="lever",
                source_type=SourceType.RECRUITING,
                provider="lever",
                event_type="lever_opportunities",
                raw_data={
                    "response": [
                        {
                            "id": "LEVER-001",
                            "name": "Lever candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LEVER-002",
                            "name": "Lever candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LEVER-003",
                            "name": "Lever candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LEVER-004",
                            "name": "Lever candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="lever",
                source_type=SourceType.RECRUITING,
                provider="lever",
                event_type="lever_postings",
                raw_data={
                    "response": [
                        {
                            "id": "LEVER-001",
                            "name": "Lever candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LEVER-002",
                            "name": "Lever candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LEVER-003",
                            "name": "Lever candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LEVER-004",
                            "name": "Lever candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Ashby
# ---------------------------------------------------------------------------
class DemoAshbyConnector(BaseConnector):
    """Simulates Ashby collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ashby",
            source_type=SourceType.RECRUITING,
            provider="ashby",
        )

        result.events.append(
            RawEventData(
                source="ashby",
                source_type=SourceType.RECRUITING,
                provider="ashby",
                event_type="ashby_candidates",
                raw_data={
                    "response": [
                        {
                            "id": "ASHBY-001",
                            "name": "Ashby candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ASHBY-002",
                            "name": "Ashby candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ASHBY-003",
                            "name": "Ashby candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ASHBY-004",
                            "name": "Ashby candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ashby",
                source_type=SourceType.RECRUITING,
                provider="ashby",
                event_type="ashby_jobs",
                raw_data={
                    "response": [
                        {
                            "id": "ASHBY-001",
                            "name": "Ashby candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ASHBY-002",
                            "name": "Ashby candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ASHBY-003",
                            "name": "Ashby candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ASHBY-004",
                            "name": "Ashby candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# SmartRecruiters
# ---------------------------------------------------------------------------
class DemoSmartRecruitersConnector(BaseConnector):
    """Simulates SmartRecruiters collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="smartrecruiters",
            source_type=SourceType.RECRUITING,
            provider="smartrecruiters",
        )

        result.events.append(
            RawEventData(
                source="smartrecruiters",
                source_type=SourceType.RECRUITING,
                provider="smartrecruiters",
                event_type="smartrecruiters_jobs",
                raw_data={
                    "response": [
                        {
                            "id": "SMARTRECRUITERS-001",
                            "name": "SmartRecruiters candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SMARTRECRUITERS-002",
                            "name": "SmartRecruiters candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SMARTRECRUITERS-003",
                            "name": "SmartRecruiters candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SMARTRECRUITERS-004",
                            "name": "SmartRecruiters candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="smartrecruiters",
                source_type=SourceType.RECRUITING,
                provider="smartrecruiters",
                event_type="smartrecruiters_candidates",
                raw_data={
                    "response": [
                        {
                            "id": "SMARTRECRUITERS-001",
                            "name": "SmartRecruiters candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SMARTRECRUITERS-002",
                            "name": "SmartRecruiters candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SMARTRECRUITERS-003",
                            "name": "SmartRecruiters candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SMARTRECRUITERS-004",
                            "name": "SmartRecruiters candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Teamtailor
# ---------------------------------------------------------------------------
class DemoTeamtailorConnector(BaseConnector):
    """Simulates Teamtailor collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="teamtailor",
            source_type=SourceType.RECRUITING,
            provider="teamtailor",
        )

        result.events.append(
            RawEventData(
                source="teamtailor",
                source_type=SourceType.RECRUITING,
                provider="teamtailor",
                event_type="teamtailor_candidates",
                raw_data={
                    "response": [
                        {
                            "id": "TEAMTAILOR-001",
                            "name": "Teamtailor candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TEAMTAILOR-002",
                            "name": "Teamtailor candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TEAMTAILOR-003",
                            "name": "Teamtailor candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TEAMTAILOR-004",
                            "name": "Teamtailor candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="teamtailor",
                source_type=SourceType.RECRUITING,
                provider="teamtailor",
                event_type="teamtailor_jobs",
                raw_data={
                    "response": [
                        {
                            "id": "TEAMTAILOR-001",
                            "name": "Teamtailor candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TEAMTAILOR-002",
                            "name": "Teamtailor candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TEAMTAILOR-003",
                            "name": "Teamtailor candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TEAMTAILOR-004",
                            "name": "Teamtailor candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Workable
# ---------------------------------------------------------------------------
class DemoWorkableConnector(BaseConnector):
    """Simulates Workable collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="workable",
            source_type=SourceType.RECRUITING,
            provider="workable",
        )

        result.events.append(
            RawEventData(
                source="workable",
                source_type=SourceType.RECRUITING,
                provider="workable",
                event_type="workable_candidates",
                raw_data={
                    "response": [
                        {
                            "id": "WORKABLE-001",
                            "name": "Workable candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WORKABLE-002",
                            "name": "Workable candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WORKABLE-003",
                            "name": "Workable candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WORKABLE-004",
                            "name": "Workable candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="workable",
                source_type=SourceType.RECRUITING,
                provider="workable",
                event_type="workable_jobs",
                raw_data={
                    "response": [
                        {
                            "id": "WORKABLE-001",
                            "name": "Workable candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WORKABLE-002",
                            "name": "Workable candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WORKABLE-003",
                            "name": "Workable candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WORKABLE-004",
                            "name": "Workable candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="workable",
                source_type=SourceType.RECRUITING,
                provider="workable",
                event_type="workable_members",
                raw_data={
                    "response": [
                        {
                            "id": "WORKABLE-001",
                            "name": "Workable candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WORKABLE-002",
                            "name": "Workable candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WORKABLE-003",
                            "name": "Workable candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WORKABLE-004",
                            "name": "Workable candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Checkr
# ---------------------------------------------------------------------------
class DemoCheckrConnector(BaseConnector):
    """Simulates Checkr collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="checkr",
            source_type=SourceType.RECRUITING,
            provider="checkr",
        )

        result.events.append(
            RawEventData(
                source="checkr",
                source_type=SourceType.RECRUITING,
                provider="checkr",
                event_type="checkr_candidates",
                raw_data={
                    "response": [
                        {
                            "id": "CHECKR-001",
                            "name": "Checkr candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CHECKR-002",
                            "name": "Checkr candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CHECKR-003",
                            "name": "Checkr candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CHECKR-004",
                            "name": "Checkr candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="checkr",
                source_type=SourceType.RECRUITING,
                provider="checkr",
                event_type="checkr_reports",
                raw_data={
                    "response": [
                        {
                            "id": "CHECKR-001",
                            "name": "Checkr candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CHECKR-002",
                            "name": "Checkr candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CHECKR-003",
                            "name": "Checkr candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CHECKR-004",
                            "name": "Checkr candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="checkr",
                source_type=SourceType.RECRUITING,
                provider="checkr",
                event_type="checkr_invitations",
                raw_data={
                    "response": [
                        {
                            "id": "CHECKR-001",
                            "name": "Checkr candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CHECKR-002",
                            "name": "Checkr candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CHECKR-003",
                            "name": "Checkr candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CHECKR-004",
                            "name": "Checkr candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Certn
# ---------------------------------------------------------------------------
class DemoCertnConnector(BaseConnector):
    """Simulates Certn collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="certn",
            source_type=SourceType.RECRUITING,
            provider="certn",
        )

        result.events.append(
            RawEventData(
                source="certn",
                source_type=SourceType.RECRUITING,
                provider="certn",
                event_type="certn_applications",
                raw_data={
                    "response": [
                        {
                            "id": "CERTN-001",
                            "name": "Certn candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CERTN-002",
                            "name": "Certn candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CERTN-003",
                            "name": "Certn candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CERTN-004",
                            "name": "Certn candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="certn",
                source_type=SourceType.RECRUITING,
                provider="certn",
                event_type="certn_reports",
                raw_data={
                    "response": [
                        {
                            "id": "CERTN-001",
                            "name": "Certn candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CERTN-002",
                            "name": "Certn candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CERTN-003",
                            "name": "Certn candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CERTN-004",
                            "name": "Certn candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# HireRight
# ---------------------------------------------------------------------------
class DemoHireRightConnector(BaseConnector):
    """Simulates HireRight collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="hireright",
            source_type=SourceType.RECRUITING,
            provider="hireright",
        )

        result.events.append(
            RawEventData(
                source="hireright",
                source_type=SourceType.RECRUITING,
                provider="hireright",
                event_type="hireright_screenings",
                raw_data={
                    "response": [
                        {
                            "id": "HIRERIGHT-001",
                            "name": "HireRight candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HIRERIGHT-002",
                            "name": "HireRight candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HIRERIGHT-003",
                            "name": "HireRight candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HIRERIGHT-004",
                            "name": "HireRight candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hireright",
                source_type=SourceType.RECRUITING,
                provider="hireright",
                event_type="hireright_candidates",
                raw_data={
                    "response": [
                        {
                            "id": "HIRERIGHT-001",
                            "name": "HireRight candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HIRERIGHT-002",
                            "name": "HireRight candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HIRERIGHT-003",
                            "name": "HireRight candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HIRERIGHT-004",
                            "name": "HireRight candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Sterling
# ---------------------------------------------------------------------------
class DemoSterlingConnector(BaseConnector):
    """Simulates Sterling collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sterling",
            source_type=SourceType.RECRUITING,
            provider="sterling",
        )

        result.events.append(
            RawEventData(
                source="sterling",
                source_type=SourceType.RECRUITING,
                provider="sterling",
                event_type="sterling_screenings",
                raw_data={
                    "response": [
                        {
                            "id": "STERLING-001",
                            "name": "Sterling candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "STERLING-002",
                            "name": "Sterling candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "STERLING-003",
                            "name": "Sterling candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "STERLING-004",
                            "name": "Sterling candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sterling",
                source_type=SourceType.RECRUITING,
                provider="sterling",
                event_type="sterling_candidates",
                raw_data={
                    "response": [
                        {
                            "id": "STERLING-001",
                            "name": "Sterling candidate 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "STERLING-002",
                            "name": "Sterling candidate 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "STERLING-003",
                            "name": "Sterling candidate 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "STERLING-004",
                            "name": "Sterling candidate 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# 360Learning
# ---------------------------------------------------------------------------
class DemoThree60LearningConnector(BaseConnector):
    """Simulates 360Learning collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="three60learning",
            source_type=SourceType.LMS,
            provider="three60learning",
        )

        result.events.append(
            RawEventData(
                source="three60learning",
                source_type=SourceType.LMS,
                provider="three60learning",
                event_type="three60learning_users",
                raw_data={
                    "response": [
                        {
                            "id": "THREE60LEARNING-001",
                            "name": "360Learning learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "THREE60LEARNING-002",
                            "name": "360Learning learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "THREE60LEARNING-003",
                            "name": "360Learning learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "THREE60LEARNING-004",
                            "name": "360Learning learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="three60learning",
                source_type=SourceType.LMS,
                provider="three60learning",
                event_type="three60learning_courses",
                raw_data={
                    "response": [
                        {
                            "id": "THREE60LEARNING-001",
                            "name": "360Learning learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "THREE60LEARNING-002",
                            "name": "360Learning learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "THREE60LEARNING-003",
                            "name": "360Learning learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "THREE60LEARNING-004",
                            "name": "360Learning learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="three60learning",
                source_type=SourceType.LMS,
                provider="three60learning",
                event_type="three60learning_enrollments",
                raw_data={
                    "response": [
                        {
                            "id": "THREE60LEARNING-001",
                            "name": "360Learning learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "THREE60LEARNING-002",
                            "name": "360Learning learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "THREE60LEARNING-003",
                            "name": "360Learning learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "THREE60LEARNING-004",
                            "name": "360Learning learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Cornerstone
# ---------------------------------------------------------------------------
class DemoCornerstoneConnector(BaseConnector):
    """Simulates Cornerstone collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cornerstone",
            source_type=SourceType.LMS,
            provider="cornerstone",
        )

        result.events.append(
            RawEventData(
                source="cornerstone",
                source_type=SourceType.LMS,
                provider="cornerstone",
                event_type="cornerstone_users",
                raw_data={
                    "response": [
                        {
                            "id": "CORNERSTONE-001",
                            "name": "Cornerstone learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CORNERSTONE-002",
                            "name": "Cornerstone learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CORNERSTONE-003",
                            "name": "Cornerstone learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CORNERSTONE-004",
                            "name": "Cornerstone learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cornerstone",
                source_type=SourceType.LMS,
                provider="cornerstone",
                event_type="cornerstone_learning_objects",
                raw_data={
                    "response": [
                        {
                            "id": "CORNERSTONE-001",
                            "name": "Cornerstone learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CORNERSTONE-002",
                            "name": "Cornerstone learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CORNERSTONE-003",
                            "name": "Cornerstone learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CORNERSTONE-004",
                            "name": "Cornerstone learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cornerstone",
                source_type=SourceType.LMS,
                provider="cornerstone",
                event_type="cornerstone_transcripts",
                raw_data={
                    "response": [
                        {
                            "id": "CORNERSTONE-001",
                            "name": "Cornerstone learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CORNERSTONE-002",
                            "name": "Cornerstone learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CORNERSTONE-003",
                            "name": "Cornerstone learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CORNERSTONE-004",
                            "name": "Cornerstone learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Coursera
# ---------------------------------------------------------------------------
class DemoCourseraConnector(BaseConnector):
    """Simulates Coursera collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="coursera",
            source_type=SourceType.LMS,
            provider="coursera",
        )

        result.events.append(
            RawEventData(
                source="coursera",
                source_type=SourceType.LMS,
                provider="coursera",
                event_type="coursera_programs",
                raw_data={
                    "response": [
                        {
                            "id": "COURSERA-001",
                            "name": "Coursera learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "COURSERA-002",
                            "name": "Coursera learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "COURSERA-003",
                            "name": "Coursera learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "COURSERA-004",
                            "name": "Coursera learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="coursera",
                source_type=SourceType.LMS,
                provider="coursera",
                event_type="coursera_enrollments",
                raw_data={
                    "response": [
                        {
                            "id": "COURSERA-001",
                            "name": "Coursera learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "COURSERA-002",
                            "name": "Coursera learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "COURSERA-003",
                            "name": "Coursera learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "COURSERA-004",
                            "name": "Coursera learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# EasyLlama
# ---------------------------------------------------------------------------
class DemoEasyLlamaConnector(BaseConnector):
    """Simulates EasyLlama collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="easyllama",
            source_type=SourceType.LMS,
            provider="easyllama",
        )

        result.events.append(
            RawEventData(
                source="easyllama",
                source_type=SourceType.LMS,
                provider="easyllama",
                event_type="easyllama_learners",
                raw_data={
                    "response": [
                        {
                            "id": "EASYLLAMA-001",
                            "name": "EasyLlama learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EASYLLAMA-002",
                            "name": "EasyLlama learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EASYLLAMA-003",
                            "name": "EasyLlama learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "EASYLLAMA-004",
                            "name": "EasyLlama learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="easyllama",
                source_type=SourceType.LMS,
                provider="easyllama",
                event_type="easyllama_trainings",
                raw_data={
                    "response": [
                        {
                            "id": "EASYLLAMA-001",
                            "name": "EasyLlama learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EASYLLAMA-002",
                            "name": "EasyLlama learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EASYLLAMA-003",
                            "name": "EasyLlama learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "EASYLLAMA-004",
                            "name": "EasyLlama learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="easyllama",
                source_type=SourceType.LMS,
                provider="easyllama",
                event_type="easyllama_completions",
                raw_data={
                    "response": [
                        {
                            "id": "EASYLLAMA-001",
                            "name": "EasyLlama learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EASYLLAMA-002",
                            "name": "EasyLlama learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EASYLLAMA-003",
                            "name": "EasyLlama learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "EASYLLAMA-004",
                            "name": "EasyLlama learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Infosec IQ
# ---------------------------------------------------------------------------
class DemoInfosecIQConnector(BaseConnector):
    """Simulates Infosec IQ collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="infosec_iq",
            source_type=SourceType.LMS,
            provider="infosec_iq",
        )

        result.events.append(
            RawEventData(
                source="infosec_iq",
                source_type=SourceType.LMS,
                provider="infosec_iq",
                event_type="infosec_learners",
                raw_data={
                    "response": [
                        {
                            "id": "INFOSEC_IQ-001",
                            "name": "Infosec IQ learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INFOSEC_IQ-002",
                            "name": "Infosec IQ learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INFOSEC_IQ-003",
                            "name": "Infosec IQ learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INFOSEC_IQ-004",
                            "name": "Infosec IQ learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="infosec_iq",
                source_type=SourceType.LMS,
                provider="infosec_iq",
                event_type="infosec_campaigns",
                raw_data={
                    "response": [
                        {
                            "id": "INFOSEC_IQ-001",
                            "name": "Infosec IQ learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INFOSEC_IQ-002",
                            "name": "Infosec IQ learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INFOSEC_IQ-003",
                            "name": "Infosec IQ learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INFOSEC_IQ-004",
                            "name": "Infosec IQ learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="infosec_iq",
                source_type=SourceType.LMS,
                provider="infosec_iq",
                event_type="infosec_completions",
                raw_data={
                    "response": [
                        {
                            "id": "INFOSEC_IQ-001",
                            "name": "Infosec IQ learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INFOSEC_IQ-002",
                            "name": "Infosec IQ learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INFOSEC_IQ-003",
                            "name": "Infosec IQ learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INFOSEC_IQ-004",
                            "name": "Infosec IQ learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# LinkedIn Learning
# ---------------------------------------------------------------------------
class DemoLinkedInLearningConnector(BaseConnector):
    """Simulates LinkedIn Learning collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="linkedin_learning",
            source_type=SourceType.LMS,
            provider="linkedin_learning",
        )

        result.events.append(
            RawEventData(
                source="linkedin_learning",
                source_type=SourceType.LMS,
                provider="linkedin_learning",
                event_type="linkedin_learning_assets",
                raw_data={
                    "response": [
                        {
                            "id": "LINKEDIN_LEARNING-001",
                            "name": "LinkedIn Learning learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LINKEDIN_LEARNING-002",
                            "name": "LinkedIn Learning learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LINKEDIN_LEARNING-003",
                            "name": "LinkedIn Learning learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LINKEDIN_LEARNING-004",
                            "name": "LinkedIn Learning learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="linkedin_learning",
                source_type=SourceType.LMS,
                provider="linkedin_learning",
                event_type="linkedin_learning_completions",
                raw_data={
                    "response": [
                        {
                            "id": "LINKEDIN_LEARNING-001",
                            "name": "LinkedIn Learning learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "LINKEDIN_LEARNING-002",
                            "name": "LinkedIn Learning learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "LINKEDIN_LEARNING-003",
                            "name": "LinkedIn Learning learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "LINKEDIN_LEARNING-004",
                            "name": "LinkedIn Learning learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# TalentLMS
# ---------------------------------------------------------------------------
class DemoTalentLMSConnector(BaseConnector):
    """Simulates TalentLMS collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="talentlms",
            source_type=SourceType.LMS,
            provider="talentlms",
        )

        result.events.append(
            RawEventData(
                source="talentlms",
                source_type=SourceType.LMS,
                provider="talentlms",
                event_type="talentlms_users",
                raw_data={
                    "response": [
                        {
                            "id": "TALENTLMS-001",
                            "name": "TalentLMS learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TALENTLMS-002",
                            "name": "TalentLMS learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TALENTLMS-003",
                            "name": "TalentLMS learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TALENTLMS-004",
                            "name": "TalentLMS learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="talentlms",
                source_type=SourceType.LMS,
                provider="talentlms",
                event_type="talentlms_courses",
                raw_data={
                    "response": [
                        {
                            "id": "TALENTLMS-001",
                            "name": "TalentLMS learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TALENTLMS-002",
                            "name": "TalentLMS learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TALENTLMS-003",
                            "name": "TalentLMS learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TALENTLMS-004",
                            "name": "TalentLMS learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="talentlms",
                source_type=SourceType.LMS,
                provider="talentlms",
                event_type="talentlms_completions",
                raw_data={
                    "response": [
                        {
                            "id": "TALENTLMS-001",
                            "name": "TalentLMS learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TALENTLMS-002",
                            "name": "TalentLMS learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TALENTLMS-003",
                            "name": "TalentLMS learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TALENTLMS-004",
                            "name": "TalentLMS learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Udemy
# ---------------------------------------------------------------------------
class DemoUdemyConnector(BaseConnector):
    """Simulates Udemy collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="udemy",
            source_type=SourceType.LMS,
            provider="udemy",
        )

        result.events.append(
            RawEventData(
                source="udemy",
                source_type=SourceType.LMS,
                provider="udemy",
                event_type="udemy_users",
                raw_data={
                    "response": [
                        {
                            "id": "UDEMY-001",
                            "name": "Udemy learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "UDEMY-002",
                            "name": "Udemy learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "UDEMY-003",
                            "name": "Udemy learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "UDEMY-004",
                            "name": "Udemy learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="udemy",
                source_type=SourceType.LMS,
                provider="udemy",
                event_type="udemy_courses",
                raw_data={
                    "response": [
                        {
                            "id": "UDEMY-001",
                            "name": "Udemy learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "UDEMY-002",
                            "name": "Udemy learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "UDEMY-003",
                            "name": "Udemy learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "UDEMY-004",
                            "name": "Udemy learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="udemy",
                source_type=SourceType.LMS,
                provider="udemy",
                event_type="udemy_analytics",
                raw_data={
                    "response": [
                        {
                            "id": "UDEMY-001",
                            "name": "Udemy learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "UDEMY-002",
                            "name": "Udemy learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "UDEMY-003",
                            "name": "Udemy learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "UDEMY-004",
                            "name": "Udemy learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Docebo
# ---------------------------------------------------------------------------
class DemoDoceboConnector(BaseConnector):
    """Simulates Docebo collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="docebo",
            source_type=SourceType.LMS,
            provider="docebo",
        )

        result.events.append(
            RawEventData(
                source="docebo",
                source_type=SourceType.LMS,
                provider="docebo",
                event_type="docebo_users",
                raw_data={
                    "response": [
                        {
                            "id": "DOCEBO-001",
                            "name": "Docebo learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOCEBO-002",
                            "name": "Docebo learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOCEBO-003",
                            "name": "Docebo learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOCEBO-004",
                            "name": "Docebo learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="docebo",
                source_type=SourceType.LMS,
                provider="docebo",
                event_type="docebo_courses",
                raw_data={
                    "response": [
                        {
                            "id": "DOCEBO-001",
                            "name": "Docebo learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOCEBO-002",
                            "name": "Docebo learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOCEBO-003",
                            "name": "Docebo learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOCEBO-004",
                            "name": "Docebo learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="docebo",
                source_type=SourceType.LMS,
                provider="docebo",
                event_type="docebo_enrollments",
                raw_data={
                    "response": [
                        {
                            "id": "DOCEBO-001",
                            "name": "Docebo learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOCEBO-002",
                            "name": "Docebo learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOCEBO-003",
                            "name": "Docebo learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOCEBO-004",
                            "name": "Docebo learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# GO1
# ---------------------------------------------------------------------------
class DemoGO1Connector(BaseConnector):
    """Simulates GO1 collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="go1",
            source_type=SourceType.LMS,
            provider="go1",
        )

        result.events.append(
            RawEventData(
                source="go1",
                source_type=SourceType.LMS,
                provider="go1",
                event_type="go1_enrollments",
                raw_data={
                    "response": [
                        {
                            "id": "GO1-001",
                            "name": "GO1 learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GO1-002",
                            "name": "GO1 learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GO1-003",
                            "name": "GO1 learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GO1-004",
                            "name": "GO1 learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="go1",
                source_type=SourceType.LMS,
                provider="go1",
                event_type="go1_learning_objects",
                raw_data={
                    "response": [
                        {
                            "id": "GO1-001",
                            "name": "GO1 learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GO1-002",
                            "name": "GO1 learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GO1-003",
                            "name": "GO1 learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GO1-004",
                            "name": "GO1 learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# SoSafe
# ---------------------------------------------------------------------------
class DemoSoSafeConnector(BaseConnector):
    """Simulates SoSafe collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sosafe",
            source_type=SourceType.LMS,
            provider="sosafe",
        )

        result.events.append(
            RawEventData(
                source="sosafe",
                source_type=SourceType.LMS,
                provider="sosafe",
                event_type="sosafe_users",
                raw_data={
                    "response": [
                        {
                            "id": "SOSAFE-001",
                            "name": "SoSafe learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SOSAFE-002",
                            "name": "SoSafe learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SOSAFE-003",
                            "name": "SoSafe learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SOSAFE-004",
                            "name": "SoSafe learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sosafe",
                source_type=SourceType.LMS,
                provider="sosafe",
                event_type="sosafe_campaigns",
                raw_data={
                    "response": [
                        {
                            "id": "SOSAFE-001",
                            "name": "SoSafe learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SOSAFE-002",
                            "name": "SoSafe learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SOSAFE-003",
                            "name": "SoSafe learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SOSAFE-004",
                            "name": "SoSafe learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sosafe",
                source_type=SourceType.LMS,
                provider="sosafe",
                event_type="sosafe_results",
                raw_data={
                    "response": [
                        {
                            "id": "SOSAFE-001",
                            "name": "SoSafe learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SOSAFE-002",
                            "name": "SoSafe learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SOSAFE-003",
                            "name": "SoSafe learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SOSAFE-004",
                            "name": "SoSafe learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Moxso
# ---------------------------------------------------------------------------
class DemoMoxsoConnector(BaseConnector):
    """Simulates Moxso collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="moxso",
            source_type=SourceType.LMS,
            provider="moxso",
        )

        result.events.append(
            RawEventData(
                source="moxso",
                source_type=SourceType.LMS,
                provider="moxso",
                event_type="moxso_users",
                raw_data={
                    "response": [
                        {
                            "id": "MOXSO-001",
                            "name": "Moxso learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MOXSO-002",
                            "name": "Moxso learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MOXSO-003",
                            "name": "Moxso learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MOXSO-004",
                            "name": "Moxso learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="moxso",
                source_type=SourceType.LMS,
                provider="moxso",
                event_type="moxso_simulations",
                raw_data={
                    "response": [
                        {
                            "id": "MOXSO-001",
                            "name": "Moxso learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MOXSO-002",
                            "name": "Moxso learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MOXSO-003",
                            "name": "Moxso learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MOXSO-004",
                            "name": "Moxso learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# AwareGO
# ---------------------------------------------------------------------------
class DemoAwareGOConnector(BaseConnector):
    """Simulates AwareGO collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="awarego",
            source_type=SourceType.LMS,
            provider="awarego",
        )

        result.events.append(
            RawEventData(
                source="awarego",
                source_type=SourceType.LMS,
                provider="awarego",
                event_type="awarego_employees",
                raw_data={
                    "response": [
                        {
                            "id": "AWAREGO-001",
                            "name": "AwareGO learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWAREGO-002",
                            "name": "AwareGO learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWAREGO-003",
                            "name": "AwareGO learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AWAREGO-004",
                            "name": "AwareGO learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="awarego",
                source_type=SourceType.LMS,
                provider="awarego",
                event_type="awarego_trainings",
                raw_data={
                    "response": [
                        {
                            "id": "AWAREGO-001",
                            "name": "AwareGO learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWAREGO-002",
                            "name": "AwareGO learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWAREGO-003",
                            "name": "AwareGO learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AWAREGO-004",
                            "name": "AwareGO learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# CyberReady
# ---------------------------------------------------------------------------
class DemoCyberReadyConnector(BaseConnector):
    """Simulates CyberReady collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cybeready",
            source_type=SourceType.LMS,
            provider="cybeready",
        )

        result.events.append(
            RawEventData(
                source="cybeready",
                source_type=SourceType.LMS,
                provider="cybeready",
                event_type="cybeready_employees",
                raw_data={
                    "response": [
                        {
                            "id": "CYBEREADY-001",
                            "name": "CyberReady learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CYBEREADY-002",
                            "name": "CyberReady learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CYBEREADY-003",
                            "name": "CyberReady learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CYBEREADY-004",
                            "name": "CyberReady learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cybeready",
                source_type=SourceType.LMS,
                provider="cybeready",
                event_type="cybeready_campaigns",
                raw_data={
                    "response": [
                        {
                            "id": "CYBEREADY-001",
                            "name": "CyberReady learner 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CYBEREADY-002",
                            "name": "CyberReady learner 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CYBEREADY-003",
                            "name": "CyberReady learner 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CYBEREADY-004",
                            "name": "CyberReady learner 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Hexnode UEM
# ---------------------------------------------------------------------------
class DemoHexnodeConnector(BaseConnector):
    """Simulates Hexnode UEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="hexnode",
            source_type=SourceType.MDM,
            provider="hexnode",
        )

        result.events.append(
            RawEventData(
                source="hexnode",
                source_type=SourceType.MDM,
                provider="hexnode",
                event_type="hexnode_devices",
                raw_data={
                    "response": [
                        {
                            "id": "HEXNODE-001",
                            "name": "Hexnode UEM device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HEXNODE-002",
                            "name": "Hexnode UEM device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HEXNODE-003",
                            "name": "Hexnode UEM device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HEXNODE-004",
                            "name": "Hexnode UEM device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hexnode",
                source_type=SourceType.MDM,
                provider="hexnode",
                event_type="hexnode_policies",
                raw_data={
                    "response": [
                        {
                            "id": "HEXNODE-001",
                            "name": "Hexnode UEM device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HEXNODE-002",
                            "name": "Hexnode UEM device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HEXNODE-003",
                            "name": "Hexnode UEM device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HEXNODE-004",
                            "name": "Hexnode UEM device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hexnode",
                source_type=SourceType.MDM,
                provider="hexnode",
                event_type="hexnode_users",
                raw_data={
                    "response": [
                        {
                            "id": "HEXNODE-001",
                            "name": "Hexnode UEM device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HEXNODE-002",
                            "name": "Hexnode UEM device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HEXNODE-003",
                            "name": "Hexnode UEM device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HEXNODE-004",
                            "name": "Hexnode UEM device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# NinjaOne
# ---------------------------------------------------------------------------
class DemoNinjaOneConnector(BaseConnector):
    """Simulates NinjaOne collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ninjaone",
            source_type=SourceType.MDM,
            provider="ninjaone",
        )

        result.events.append(
            RawEventData(
                source="ninjaone",
                source_type=SourceType.MDM,
                provider="ninjaone",
                event_type="ninjaone_devices",
                raw_data={
                    "response": [
                        {
                            "id": "NINJAONE-001",
                            "name": "NinjaOne device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NINJAONE-002",
                            "name": "NinjaOne device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NINJAONE-003",
                            "name": "NinjaOne device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NINJAONE-004",
                            "name": "NinjaOne device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ninjaone",
                source_type=SourceType.MDM,
                provider="ninjaone",
                event_type="ninjaone_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "NINJAONE-001",
                            "name": "NinjaOne device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NINJAONE-002",
                            "name": "NinjaOne device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NINJAONE-003",
                            "name": "NinjaOne device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NINJAONE-004",
                            "name": "NinjaOne device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ninjaone",
                source_type=SourceType.MDM,
                provider="ninjaone",
                event_type="ninjaone_policies",
                raw_data={
                    "response": [
                        {
                            "id": "NINJAONE-001",
                            "name": "NinjaOne device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NINJAONE-002",
                            "name": "NinjaOne device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NINJAONE-003",
                            "name": "NinjaOne device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NINJAONE-004",
                            "name": "NinjaOne device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Kolide
# ---------------------------------------------------------------------------
class DemoKolideConnector(BaseConnector):
    """Simulates Kolide collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="kolide",
            source_type=SourceType.MDM,
            provider="kolide",
        )

        result.events.append(
            RawEventData(
                source="kolide",
                source_type=SourceType.MDM,
                provider="kolide",
                event_type="kolide_devices",
                raw_data={
                    "response": [
                        {
                            "id": "KOLIDE-001",
                            "name": "Kolide device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KOLIDE-002",
                            "name": "Kolide device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KOLIDE-003",
                            "name": "Kolide device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KOLIDE-004",
                            "name": "Kolide device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="kolide",
                source_type=SourceType.MDM,
                provider="kolide",
                event_type="kolide_checks",
                raw_data={
                    "response": [
                        {
                            "id": "KOLIDE-001",
                            "name": "Kolide device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KOLIDE-002",
                            "name": "Kolide device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KOLIDE-003",
                            "name": "Kolide device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KOLIDE-004",
                            "name": "Kolide device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="kolide",
                source_type=SourceType.MDM,
                provider="kolide",
                event_type="kolide_issues",
                raw_data={
                    "response": [
                        {
                            "id": "KOLIDE-001",
                            "name": "Kolide device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KOLIDE-002",
                            "name": "Kolide device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KOLIDE-003",
                            "name": "Kolide device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KOLIDE-004",
                            "name": "Kolide device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Addigy
# ---------------------------------------------------------------------------
class DemoAddigyConnector(BaseConnector):
    """Simulates Addigy collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="addigy",
            source_type=SourceType.MDM,
            provider="addigy",
        )

        result.events.append(
            RawEventData(
                source="addigy",
                source_type=SourceType.MDM,
                provider="addigy",
                event_type="addigy_devices",
                raw_data={
                    "response": [
                        {
                            "id": "ADDIGY-001",
                            "name": "Addigy device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ADDIGY-002",
                            "name": "Addigy device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ADDIGY-003",
                            "name": "Addigy device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ADDIGY-004",
                            "name": "Addigy device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="addigy",
                source_type=SourceType.MDM,
                provider="addigy",
                event_type="addigy_policies",
                raw_data={
                    "response": [
                        {
                            "id": "ADDIGY-001",
                            "name": "Addigy device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ADDIGY-002",
                            "name": "Addigy device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ADDIGY-003",
                            "name": "Addigy device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ADDIGY-004",
                            "name": "Addigy device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Miradore
# ---------------------------------------------------------------------------
class DemoMiradoreConnector(BaseConnector):
    """Simulates Miradore collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="miradore",
            source_type=SourceType.MDM,
            provider="miradore",
        )

        result.events.append(
            RawEventData(
                source="miradore",
                source_type=SourceType.MDM,
                provider="miradore",
                event_type="miradore_devices",
                raw_data={
                    "response": [
                        {
                            "id": "MIRADORE-001",
                            "name": "Miradore device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MIRADORE-002",
                            "name": "Miradore device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MIRADORE-003",
                            "name": "Miradore device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MIRADORE-004",
                            "name": "Miradore device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="miradore",
                source_type=SourceType.MDM,
                provider="miradore",
                event_type="miradore_applications",
                raw_data={
                    "response": [
                        {
                            "id": "MIRADORE-001",
                            "name": "Miradore device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MIRADORE-002",
                            "name": "Miradore device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MIRADORE-003",
                            "name": "Miradore device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MIRADORE-004",
                            "name": "Miradore device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Aikido
# ---------------------------------------------------------------------------
class DemoAikidoConnector(BaseConnector):
    """Simulates Aikido collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aikido",
            source_type=SourceType.SCANNER,
            provider="aikido",
        )

        result.events.append(
            RawEventData(
                source="aikido",
                source_type=SourceType.SCANNER,
                provider="aikido",
                event_type="aikido_issues",
                raw_data={
                    "response": [
                        {
                            "id": "AIKIDO-001",
                            "name": "Aikido finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AIKIDO-002",
                            "name": "Aikido finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AIKIDO-003",
                            "name": "Aikido finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aikido",
                source_type=SourceType.SCANNER,
                provider="aikido",
                event_type="aikido_repositories",
                raw_data={
                    "response": [
                        {
                            "id": "AIKIDO-001",
                            "name": "Aikido finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AIKIDO-002",
                            "name": "Aikido finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AIKIDO-003",
                            "name": "Aikido finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aikido",
                source_type=SourceType.SCANNER,
                provider="aikido",
                event_type="aikido_code_repos",
                raw_data={
                    "response": [
                        {
                            "id": "AIKIDO-001",
                            "name": "Aikido finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AIKIDO-002",
                            "name": "Aikido finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AIKIDO-003",
                            "name": "Aikido finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# SonarCloud
# ---------------------------------------------------------------------------
class DemoSonarCloudConnector(BaseConnector):
    """Simulates SonarCloud collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sonarcloud",
            source_type=SourceType.CODE,
            provider="sonarcloud",
        )

        result.events.append(
            RawEventData(
                source="sonarcloud",
                source_type=SourceType.CODE,
                provider="sonarcloud",
                event_type="sonarcloud_projects",
                raw_data={
                    "response": [
                        {
                            "id": "SONARCLOUD-001",
                            "name": "SonarCloud repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SONARCLOUD-002",
                            "name": "SonarCloud repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SONARCLOUD-003",
                            "name": "SonarCloud repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sonarcloud",
                source_type=SourceType.CODE,
                provider="sonarcloud",
                event_type="sonarcloud_issues",
                raw_data={
                    "response": [
                        {
                            "id": "SONARCLOUD-001",
                            "name": "SonarCloud repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SONARCLOUD-002",
                            "name": "SonarCloud repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SONARCLOUD-003",
                            "name": "SonarCloud repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SONARCLOUD-004",
                            "name": "SonarCloud repo 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sonarcloud",
                source_type=SourceType.CODE,
                provider="sonarcloud",
                event_type="sonarcloud_measures",
                raw_data={
                    "response": [
                        {
                            "id": "SONARCLOUD-001",
                            "name": "SonarCloud repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SONARCLOUD-002",
                            "name": "SonarCloud repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SONARCLOUD-003",
                            "name": "SonarCloud repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Wiz Code
# ---------------------------------------------------------------------------
class DemoWizCodeConnector(BaseConnector):
    """Simulates Wiz Code collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="wiz_code",
            source_type=SourceType.CODE,
            provider="wiz_code",
        )

        result.events.append(
            RawEventData(
                source="wiz_code",
                source_type=SourceType.CODE,
                provider="wiz_code",
                event_type="wiz_code_repos",
                raw_data={
                    "response": [
                        {
                            "id": "WIZ_CODE-001",
                            "name": "Wiz Code repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WIZ_CODE-002",
                            "name": "Wiz Code repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WIZ_CODE-003",
                            "name": "Wiz Code repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="wiz_code",
                source_type=SourceType.CODE,
                provider="wiz_code",
                event_type="wiz_code_issues",
                raw_data={
                    "response": [
                        {
                            "id": "WIZ_CODE-001",
                            "name": "Wiz Code repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WIZ_CODE-002",
                            "name": "Wiz Code repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WIZ_CODE-003",
                            "name": "Wiz Code repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WIZ_CODE-004",
                            "name": "Wiz Code repo 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Huntress
# ---------------------------------------------------------------------------
class DemoHuntressConnector(BaseConnector):
    """Simulates Huntress collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="huntress",
            source_type=SourceType.EDR,
            provider="huntress",
        )

        result.events.append(
            RawEventData(
                source="huntress",
                source_type=SourceType.EDR,
                provider="huntress",
                event_type="huntress_agents",
                raw_data={
                    "response": [
                        {
                            "id": "HUNTRESS-001",
                            "name": "Huntress endpoint 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HUNTRESS-002",
                            "name": "Huntress endpoint 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HUNTRESS-003",
                            "name": "Huntress endpoint 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="huntress",
                source_type=SourceType.EDR,
                provider="huntress",
                event_type="huntress_incidents",
                raw_data={
                    "response": [
                        {
                            "id": "HUNTRESS-001",
                            "name": "Huntress endpoint 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HUNTRESS-002",
                            "name": "Huntress endpoint 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HUNTRESS-003",
                            "name": "Huntress endpoint 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HUNTRESS-004",
                            "name": "Huntress endpoint 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="huntress",
                source_type=SourceType.EDR,
                provider="huntress",
                event_type="huntress_reports",
                raw_data={
                    "response": [
                        {
                            "id": "HUNTRESS-001",
                            "name": "Huntress endpoint 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HUNTRESS-002",
                            "name": "Huntress endpoint 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HUNTRESS-003",
                            "name": "Huntress endpoint 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Jit
# ---------------------------------------------------------------------------
class DemoJitSecurityConnector(BaseConnector):
    """Simulates Jit collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="jit_security",
            source_type=SourceType.SCANNER,
            provider="jit_security",
        )

        result.events.append(
            RawEventData(
                source="jit_security",
                source_type=SourceType.SCANNER,
                provider="jit_security",
                event_type="jit_findings",
                raw_data={
                    "response": [
                        {
                            "id": "JIT_SECURITY-001",
                            "name": "Jit finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "JIT_SECURITY-002",
                            "name": "Jit finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "JIT_SECURITY-003",
                            "name": "Jit finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="jit_security",
                source_type=SourceType.SCANNER,
                provider="jit_security",
                event_type="jit_assets",
                raw_data={
                    "response": [
                        {
                            "id": "JIT_SECURITY-001",
                            "name": "Jit finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "JIT_SECURITY-002",
                            "name": "Jit finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "JIT_SECURITY-003",
                            "name": "Jit finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Upwind
# ---------------------------------------------------------------------------
class DemoUpwindConnector(BaseConnector):
    """Simulates Upwind collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="upwind",
            source_type=SourceType.CSPM,
            provider="upwind",
        )

        result.events.append(
            RawEventData(
                source="upwind",
                source_type=SourceType.CSPM,
                provider="upwind",
                event_type="upwind_resources",
                raw_data={
                    "response": [
                        {
                            "id": "UPWIND-001",
                            "name": "Upwind resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "UPWIND-002",
                            "name": "Upwind resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "UPWIND-003",
                            "name": "Upwind resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "UPWIND-004",
                            "name": "Upwind resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="upwind",
                source_type=SourceType.CSPM,
                provider="upwind",
                event_type="upwind_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "id": "UPWIND-001",
                            "name": "Upwind resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "UPWIND-002",
                            "name": "Upwind resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "UPWIND-003",
                            "name": "Upwind resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="upwind",
                source_type=SourceType.CSPM,
                provider="upwind",
                event_type="upwind_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "UPWIND-001",
                            "name": "Upwind resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "UPWIND-002",
                            "name": "Upwind resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "UPWIND-003",
                            "name": "Upwind resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "UPWIND-004",
                            "name": "Upwind resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Arnica
# ---------------------------------------------------------------------------
class DemoArnicaConnector(BaseConnector):
    """Simulates Arnica collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="arnica",
            source_type=SourceType.CODE,
            provider="arnica",
        )

        result.events.append(
            RawEventData(
                source="arnica",
                source_type=SourceType.CODE,
                provider="arnica",
                event_type="arnica_repositories",
                raw_data={
                    "response": [
                        {
                            "id": "ARNICA-001",
                            "name": "Arnica repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ARNICA-002",
                            "name": "Arnica repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ARNICA-003",
                            "name": "Arnica repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="arnica",
                source_type=SourceType.CODE,
                provider="arnica",
                event_type="arnica_risks",
                raw_data={
                    "response": [
                        {
                            "id": "ARNICA-001",
                            "name": "Arnica repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ARNICA-002",
                            "name": "Arnica repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ARNICA-003",
                            "name": "Arnica repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ARNICA-004",
                            "name": "Arnica repo 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Pentera
# ---------------------------------------------------------------------------
class DemoPenteraConnector(BaseConnector):
    """Simulates Pentera collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="pentera",
            source_type=SourceType.SCANNER,
            provider="pentera",
        )

        result.events.append(
            RawEventData(
                source="pentera",
                source_type=SourceType.SCANNER,
                provider="pentera",
                event_type="pentera_tests",
                raw_data={
                    "response": [
                        {
                            "id": "PENTERA-001",
                            "name": "Pentera finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PENTERA-002",
                            "name": "Pentera finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PENTERA-003",
                            "name": "Pentera finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="pentera",
                source_type=SourceType.SCANNER,
                provider="pentera",
                event_type="pentera_findings",
                raw_data={
                    "response": [
                        {
                            "id": "PENTERA-001",
                            "name": "Pentera finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PENTERA-002",
                            "name": "Pentera finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PENTERA-003",
                            "name": "Pentera finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="pentera",
                source_type=SourceType.SCANNER,
                provider="pentera",
                event_type="pentera_assets",
                raw_data={
                    "response": [
                        {
                            "id": "PENTERA-001",
                            "name": "Pentera finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PENTERA-002",
                            "name": "Pentera finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PENTERA-003",
                            "name": "Pentera finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Horizon3.ai NodeZero
# ---------------------------------------------------------------------------
class DemoHorizon3Connector(BaseConnector):
    """Simulates Horizon3.ai NodeZero collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="horizon3",
            source_type=SourceType.SCANNER,
            provider="horizon3",
        )

        result.events.append(
            RawEventData(
                source="horizon3",
                source_type=SourceType.SCANNER,
                provider="horizon3",
                event_type="horizon3_pentests",
                raw_data={
                    "response": [
                        {
                            "id": "HORIZON3-001",
                            "name": "Horizon3.ai NodeZero finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HORIZON3-002",
                            "name": "Horizon3.ai NodeZero finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HORIZON3-003",
                            "name": "Horizon3.ai NodeZero finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="horizon3",
                source_type=SourceType.SCANNER,
                provider="horizon3",
                event_type="horizon3_findings",
                raw_data={
                    "response": [
                        {
                            "id": "HORIZON3-001",
                            "name": "Horizon3.ai NodeZero finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HORIZON3-002",
                            "name": "Horizon3.ai NodeZero finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HORIZON3-003",
                            "name": "Horizon3.ai NodeZero finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Bugcrowd
# ---------------------------------------------------------------------------
class DemoBugcrowdConnector(BaseConnector):
    """Simulates Bugcrowd collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="bugcrowd",
            source_type=SourceType.SCANNER,
            provider="bugcrowd",
        )

        result.events.append(
            RawEventData(
                source="bugcrowd",
                source_type=SourceType.SCANNER,
                provider="bugcrowd",
                event_type="bugcrowd_submissions",
                raw_data={
                    "response": [
                        {
                            "id": "BUGCROWD-001",
                            "name": "Bugcrowd finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BUGCROWD-002",
                            "name": "Bugcrowd finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BUGCROWD-003",
                            "name": "Bugcrowd finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="bugcrowd",
                source_type=SourceType.SCANNER,
                provider="bugcrowd",
                event_type="bugcrowd_programs",
                raw_data={
                    "response": [
                        {
                            "id": "BUGCROWD-001",
                            "name": "Bugcrowd finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BUGCROWD-002",
                            "name": "Bugcrowd finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BUGCROWD-003",
                            "name": "Bugcrowd finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Intigriti
# ---------------------------------------------------------------------------
class DemoIntigritiConnector(BaseConnector):
    """Simulates Intigriti collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="intigriti",
            source_type=SourceType.SCANNER,
            provider="intigriti",
        )

        result.events.append(
            RawEventData(
                source="intigriti",
                source_type=SourceType.SCANNER,
                provider="intigriti",
                event_type="intigriti_submissions",
                raw_data={
                    "response": [
                        {
                            "id": "INTIGRITI-001",
                            "name": "Intigriti finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INTIGRITI-002",
                            "name": "Intigriti finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INTIGRITI-003",
                            "name": "Intigriti finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="intigriti",
                source_type=SourceType.SCANNER,
                provider="intigriti",
                event_type="intigriti_programs",
                raw_data={
                    "response": [
                        {
                            "id": "INTIGRITI-001",
                            "name": "Intigriti finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INTIGRITI-002",
                            "name": "Intigriti finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INTIGRITI-003",
                            "name": "Intigriti finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Halo Security
# ---------------------------------------------------------------------------
class DemoHaloSecurityConnector(BaseConnector):
    """Simulates Halo Security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="halo_security",
            source_type=SourceType.SCANNER,
            provider="halo_security",
        )

        result.events.append(
            RawEventData(
                source="halo_security",
                source_type=SourceType.SCANNER,
                provider="halo_security",
                event_type="halo_assets",
                raw_data={
                    "response": [
                        {
                            "id": "HALO_SECURITY-001",
                            "name": "Halo Security finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HALO_SECURITY-002",
                            "name": "Halo Security finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HALO_SECURITY-003",
                            "name": "Halo Security finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="halo_security",
                source_type=SourceType.SCANNER,
                provider="halo_security",
                event_type="halo_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "id": "HALO_SECURITY-001",
                            "name": "Halo Security finding 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HALO_SECURITY-002",
                            "name": "Halo Security finding 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HALO_SECURITY-003",
                            "name": "Halo Security finding 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Traceable AI
# ---------------------------------------------------------------------------
class DemoTraceableAIConnector(BaseConnector):
    """Simulates Traceable AI collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="traceable_ai",
            source_type=SourceType.NETWORK,
            provider="traceable_ai",
        )

        result.events.append(
            RawEventData(
                source="traceable_ai",
                source_type=SourceType.NETWORK,
                provider="traceable_ai",
                event_type="traceable_apis",
                raw_data={
                    "response": [
                        {
                            "id": "TRACEABLE_AI-001",
                            "name": "Traceable AI device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRACEABLE_AI-002",
                            "name": "Traceable AI device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRACEABLE_AI-003",
                            "name": "Traceable AI device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="traceable_ai",
                source_type=SourceType.NETWORK,
                provider="traceable_ai",
                event_type="traceable_vulnerabilities",
                raw_data={
                    "response": [
                        {
                            "id": "TRACEABLE_AI-001",
                            "name": "Traceable AI device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRACEABLE_AI-002",
                            "name": "Traceable AI device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRACEABLE_AI-003",
                            "name": "Traceable AI device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TRACEABLE_AI-004",
                            "name": "Traceable AI device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="traceable_ai",
                source_type=SourceType.NETWORK,
                provider="traceable_ai",
                event_type="traceable_events",
                raw_data={
                    "response": [
                        {
                            "id": "TRACEABLE_AI-001",
                            "name": "Traceable AI device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRACEABLE_AI-002",
                            "name": "Traceable AI device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRACEABLE_AI-003",
                            "name": "Traceable AI device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Sentry
# ---------------------------------------------------------------------------
class DemoSentryConnector(BaseConnector):
    """Simulates Sentry collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sentry",
            source_type=SourceType.OBSERVABILITY,
            provider="sentry",
        )

        result.events.append(
            RawEventData(
                source="sentry",
                source_type=SourceType.OBSERVABILITY,
                provider="sentry",
                event_type="sentry_projects",
                raw_data={
                    "response": [
                        {
                            "id": "SENTRY-001",
                            "name": "Sentry monitor 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SENTRY-002",
                            "name": "Sentry monitor 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SENTRY-003",
                            "name": "Sentry monitor 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sentry",
                source_type=SourceType.OBSERVABILITY,
                provider="sentry",
                event_type="sentry_issues",
                raw_data={
                    "response": [
                        {
                            "id": "SENTRY-001",
                            "name": "Sentry monitor 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SENTRY-002",
                            "name": "Sentry monitor 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SENTRY-003",
                            "name": "Sentry monitor 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SENTRY-004",
                            "name": "Sentry monitor 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sentry",
                source_type=SourceType.OBSERVABILITY,
                provider="sentry",
                event_type="sentry_events",
                raw_data={
                    "response": [
                        {
                            "id": "SENTRY-001",
                            "name": "Sentry monitor 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SENTRY-002",
                            "name": "Sentry monitor 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SENTRY-003",
                            "name": "Sentry monitor 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Rollbar
# ---------------------------------------------------------------------------
class DemoRollbarConnector(BaseConnector):
    """Simulates Rollbar collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="rollbar",
            source_type=SourceType.OBSERVABILITY,
            provider="rollbar",
        )

        result.events.append(
            RawEventData(
                source="rollbar",
                source_type=SourceType.OBSERVABILITY,
                provider="rollbar",
                event_type="rollbar_items",
                raw_data={
                    "response": [
                        {
                            "id": "ROLLBAR-001",
                            "name": "Rollbar monitor 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ROLLBAR-002",
                            "name": "Rollbar monitor 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ROLLBAR-003",
                            "name": "Rollbar monitor 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rollbar",
                source_type=SourceType.OBSERVABILITY,
                provider="rollbar",
                event_type="rollbar_deploys",
                raw_data={
                    "response": [
                        {
                            "id": "ROLLBAR-001",
                            "name": "Rollbar monitor 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ROLLBAR-002",
                            "name": "Rollbar monitor 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ROLLBAR-003",
                            "name": "Rollbar monitor 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ROLLBAR-004",
                            "name": "Rollbar monitor 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Dynatrace
# ---------------------------------------------------------------------------
class DemoDynatraceConnector(BaseConnector):
    """Simulates Dynatrace collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="dynatrace",
            source_type=SourceType.OBSERVABILITY,
            provider="dynatrace",
        )

        result.events.append(
            RawEventData(
                source="dynatrace",
                source_type=SourceType.OBSERVABILITY,
                provider="dynatrace",
                event_type="dynatrace_entities",
                raw_data={
                    "response": [
                        {
                            "id": "DYNATRACE-001",
                            "name": "Dynatrace monitor 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DYNATRACE-002",
                            "name": "Dynatrace monitor 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DYNATRACE-003",
                            "name": "Dynatrace monitor 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dynatrace",
                source_type=SourceType.OBSERVABILITY,
                provider="dynatrace",
                event_type="dynatrace_problems",
                raw_data={
                    "response": [
                        {
                            "id": "DYNATRACE-001",
                            "name": "Dynatrace monitor 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DYNATRACE-002",
                            "name": "Dynatrace monitor 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DYNATRACE-003",
                            "name": "Dynatrace monitor 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DYNATRACE-004",
                            "name": "Dynatrace monitor 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dynatrace",
                source_type=SourceType.OBSERVABILITY,
                provider="dynatrace",
                event_type="dynatrace_security_problems",
                raw_data={
                    "response": [
                        {
                            "id": "DYNATRACE-001",
                            "name": "Dynatrace monitor 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DYNATRACE-002",
                            "name": "Dynatrace monitor 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DYNATRACE-003",
                            "name": "Dynatrace monitor 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Sumo Logic SIEM
# ---------------------------------------------------------------------------
class DemoSumoLogicNewConnector(BaseConnector):
    """Simulates Sumo Logic SIEM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sumo_logic_new",
            source_type=SourceType.SIEM,
            provider="sumo_logic_new",
        )

        result.events.append(
            RawEventData(
                source="sumo_logic_new",
                source_type=SourceType.SIEM,
                provider="sumo_logic_new",
                event_type="sumologic_collectors",
                raw_data={
                    "response": [
                        {
                            "id": "SUMO_LOGIC_NEW-001",
                            "name": "Sumo Logic SIEM event 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SUMO_LOGIC_NEW-002",
                            "name": "Sumo Logic SIEM event 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SUMO_LOGIC_NEW-003",
                            "name": "Sumo Logic SIEM event 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sumo_logic_new",
                source_type=SourceType.SIEM,
                provider="sumo_logic_new",
                event_type="sumologic_searches",
                raw_data={
                    "response": [
                        {
                            "id": "SUMO_LOGIC_NEW-001",
                            "name": "Sumo Logic SIEM event 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SUMO_LOGIC_NEW-002",
                            "name": "Sumo Logic SIEM event 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SUMO_LOGIC_NEW-003",
                            "name": "Sumo Logic SIEM event 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sumo_logic_new",
                source_type=SourceType.SIEM,
                provider="sumo_logic_new",
                event_type="sumologic_dashboards",
                raw_data={
                    "response": [
                        {
                            "id": "SUMO_LOGIC_NEW-001",
                            "name": "Sumo Logic SIEM event 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SUMO_LOGIC_NEW-002",
                            "name": "Sumo Logic SIEM event 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SUMO_LOGIC_NEW-003",
                            "name": "Sumo Logic SIEM event 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# HubSpot
# ---------------------------------------------------------------------------
class DemoHubSpotConnector(BaseConnector):
    """Simulates HubSpot collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="hubspot",
            source_type=SourceType.CRM,
            provider="hubspot",
        )

        result.events.append(
            RawEventData(
                source="hubspot",
                source_type=SourceType.CRM,
                provider="hubspot",
                event_type="hubspot_contacts",
                raw_data={
                    "response": [
                        {
                            "id": "HUBSPOT-001",
                            "name": "HubSpot contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HUBSPOT-002",
                            "name": "HubSpot contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HUBSPOT-003",
                            "name": "HubSpot contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HUBSPOT-004",
                            "name": "HubSpot contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hubspot",
                source_type=SourceType.CRM,
                provider="hubspot",
                event_type="hubspot_deals",
                raw_data={
                    "response": [
                        {
                            "id": "HUBSPOT-001",
                            "name": "HubSpot contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HUBSPOT-002",
                            "name": "HubSpot contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HUBSPOT-003",
                            "name": "HubSpot contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HUBSPOT-004",
                            "name": "HubSpot contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="hubspot",
                source_type=SourceType.CRM,
                provider="hubspot",
                event_type="hubspot_roles",
                raw_data={
                    "response": [
                        {
                            "id": "HUBSPOT-001",
                            "name": "HubSpot contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "HUBSPOT-002",
                            "name": "HubSpot contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "HUBSPOT-003",
                            "name": "HubSpot contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "HUBSPOT-004",
                            "name": "HubSpot contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Pipedrive
# ---------------------------------------------------------------------------
class DemoPipedriveConnector(BaseConnector):
    """Simulates Pipedrive collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="pipedrive",
            source_type=SourceType.CRM,
            provider="pipedrive",
        )

        result.events.append(
            RawEventData(
                source="pipedrive",
                source_type=SourceType.CRM,
                provider="pipedrive",
                event_type="pipedrive_persons",
                raw_data={
                    "response": [
                        {
                            "id": "PIPEDRIVE-001",
                            "name": "Pipedrive contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PIPEDRIVE-002",
                            "name": "Pipedrive contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PIPEDRIVE-003",
                            "name": "Pipedrive contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PIPEDRIVE-004",
                            "name": "Pipedrive contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="pipedrive",
                source_type=SourceType.CRM,
                provider="pipedrive",
                event_type="pipedrive_deals",
                raw_data={
                    "response": [
                        {
                            "id": "PIPEDRIVE-001",
                            "name": "Pipedrive contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PIPEDRIVE-002",
                            "name": "Pipedrive contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PIPEDRIVE-003",
                            "name": "Pipedrive contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PIPEDRIVE-004",
                            "name": "Pipedrive contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="pipedrive",
                source_type=SourceType.CRM,
                provider="pipedrive",
                event_type="pipedrive_users",
                raw_data={
                    "response": [
                        {
                            "id": "PIPEDRIVE-001",
                            "name": "Pipedrive contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "PIPEDRIVE-002",
                            "name": "Pipedrive contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "PIPEDRIVE-003",
                            "name": "Pipedrive contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "PIPEDRIVE-004",
                            "name": "Pipedrive contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Intercom
# ---------------------------------------------------------------------------
class DemoIntercomConnector(BaseConnector):
    """Simulates Intercom collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="intercom",
            source_type=SourceType.CRM,
            provider="intercom",
        )

        result.events.append(
            RawEventData(
                source="intercom",
                source_type=SourceType.CRM,
                provider="intercom",
                event_type="intercom_contacts",
                raw_data={
                    "response": [
                        {
                            "id": "INTERCOM-001",
                            "name": "Intercom contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INTERCOM-002",
                            "name": "Intercom contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INTERCOM-003",
                            "name": "Intercom contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INTERCOM-004",
                            "name": "Intercom contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="intercom",
                source_type=SourceType.CRM,
                provider="intercom",
                event_type="intercom_admins",
                raw_data={
                    "response": [
                        {
                            "id": "INTERCOM-001",
                            "name": "Intercom contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INTERCOM-002",
                            "name": "Intercom contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INTERCOM-003",
                            "name": "Intercom contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INTERCOM-004",
                            "name": "Intercom contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="intercom",
                source_type=SourceType.CRM,
                provider="intercom",
                event_type="intercom_conversations",
                raw_data={
                    "response": [
                        {
                            "id": "INTERCOM-001",
                            "name": "Intercom contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INTERCOM-002",
                            "name": "Intercom contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INTERCOM-003",
                            "name": "Intercom contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INTERCOM-004",
                            "name": "Intercom contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Gong
# ---------------------------------------------------------------------------
class DemoGongConnector(BaseConnector):
    """Simulates Gong collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="gong",
            source_type=SourceType.CRM,
            provider="gong",
        )

        result.events.append(
            RawEventData(
                source="gong",
                source_type=SourceType.CRM,
                provider="gong",
                event_type="gong_calls",
                raw_data={
                    "response": [
                        {
                            "id": "GONG-001",
                            "name": "Gong contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GONG-002",
                            "name": "Gong contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GONG-003",
                            "name": "Gong contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GONG-004",
                            "name": "Gong contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="gong",
                source_type=SourceType.CRM,
                provider="gong",
                event_type="gong_users",
                raw_data={
                    "response": [
                        {
                            "id": "GONG-001",
                            "name": "Gong contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GONG-002",
                            "name": "Gong contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GONG-003",
                            "name": "Gong contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GONG-004",
                            "name": "Gong contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="gong",
                source_type=SourceType.CRM,
                provider="gong",
                event_type="gong_folders",
                raw_data={
                    "response": [
                        {
                            "id": "GONG-001",
                            "name": "Gong contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GONG-002",
                            "name": "Gong contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GONG-003",
                            "name": "Gong contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GONG-004",
                            "name": "Gong contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Freshsales
# ---------------------------------------------------------------------------
class DemoFreshsalesConnector(BaseConnector):
    """Simulates Freshsales collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="freshsales",
            source_type=SourceType.CRM,
            provider="freshsales",
        )

        result.events.append(
            RawEventData(
                source="freshsales",
                source_type=SourceType.CRM,
                provider="freshsales",
                event_type="freshsales_contacts",
                raw_data={
                    "response": [
                        {
                            "id": "FRESHSALES-001",
                            "name": "Freshsales contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FRESHSALES-002",
                            "name": "Freshsales contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FRESHSALES-003",
                            "name": "Freshsales contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FRESHSALES-004",
                            "name": "Freshsales contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="freshsales",
                source_type=SourceType.CRM,
                provider="freshsales",
                event_type="freshsales_deals",
                raw_data={
                    "response": [
                        {
                            "id": "FRESHSALES-001",
                            "name": "Freshsales contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FRESHSALES-002",
                            "name": "Freshsales contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FRESHSALES-003",
                            "name": "Freshsales contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FRESHSALES-004",
                            "name": "Freshsales contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Attio
# ---------------------------------------------------------------------------
class DemoAttioConnector(BaseConnector):
    """Simulates Attio collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="attio",
            source_type=SourceType.CRM,
            provider="attio",
        )

        result.events.append(
            RawEventData(
                source="attio",
                source_type=SourceType.CRM,
                provider="attio",
                event_type="attio_people",
                raw_data={
                    "response": [
                        {
                            "id": "ATTIO-001",
                            "name": "Attio contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ATTIO-002",
                            "name": "Attio contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ATTIO-003",
                            "name": "Attio contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ATTIO-004",
                            "name": "Attio contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="attio",
                source_type=SourceType.CRM,
                provider="attio",
                event_type="attio_companies",
                raw_data={
                    "response": [
                        {
                            "id": "ATTIO-001",
                            "name": "Attio contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ATTIO-002",
                            "name": "Attio contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ATTIO-003",
                            "name": "Attio contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ATTIO-004",
                            "name": "Attio contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Copper
# ---------------------------------------------------------------------------
class DemoCopperConnector(BaseConnector):
    """Simulates Copper collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="copper",
            source_type=SourceType.CRM,
            provider="copper",
        )

        result.events.append(
            RawEventData(
                source="copper",
                source_type=SourceType.CRM,
                provider="copper",
                event_type="copper_people",
                raw_data={
                    "response": [
                        {
                            "id": "COPPER-001",
                            "name": "Copper contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "COPPER-002",
                            "name": "Copper contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "COPPER-003",
                            "name": "Copper contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "COPPER-004",
                            "name": "Copper contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="copper",
                source_type=SourceType.CRM,
                provider="copper",
                event_type="copper_opportunities",
                raw_data={
                    "response": [
                        {
                            "id": "COPPER-001",
                            "name": "Copper contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "COPPER-002",
                            "name": "Copper contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "COPPER-003",
                            "name": "Copper contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "COPPER-004",
                            "name": "Copper contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------
class DemoCloseCRMConnector(BaseConnector):
    """Simulates Close collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="close_crm",
            source_type=SourceType.CRM,
            provider="close_crm",
        )

        result.events.append(
            RawEventData(
                source="close_crm",
                source_type=SourceType.CRM,
                provider="close_crm",
                event_type="close_leads",
                raw_data={
                    "response": [
                        {
                            "id": "CLOSE_CRM-001",
                            "name": "Close contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CLOSE_CRM-002",
                            "name": "Close contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CLOSE_CRM-003",
                            "name": "Close contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CLOSE_CRM-004",
                            "name": "Close contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="close_crm",
                source_type=SourceType.CRM,
                provider="close_crm",
                event_type="close_users",
                raw_data={
                    "response": [
                        {
                            "id": "CLOSE_CRM-001",
                            "name": "Close contact 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CLOSE_CRM-002",
                            "name": "Close contact 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CLOSE_CRM-003",
                            "name": "Close contact 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CLOSE_CRM-004",
                            "name": "Close contact 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Microsoft Teams
# ---------------------------------------------------------------------------
class DemoMicrosoftTeamsConnector(BaseConnector):
    """Simulates Microsoft Teams collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="microsoft_teams",
            source_type=SourceType.COLLABORATION,
            provider="microsoft_teams",
        )

        result.events.append(
            RawEventData(
                source="microsoft_teams",
                source_type=SourceType.COLLABORATION,
                provider="microsoft_teams",
                event_type="ms_teams_list",
                raw_data={
                    "response": [
                        {
                            "id": "MICROSOFT_TEAMS-001",
                            "name": "Microsoft Teams workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MICROSOFT_TEAMS-002",
                            "name": "Microsoft Teams workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MICROSOFT_TEAMS-003",
                            "name": "Microsoft Teams workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MICROSOFT_TEAMS-004",
                            "name": "Microsoft Teams workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="microsoft_teams",
                source_type=SourceType.COLLABORATION,
                provider="microsoft_teams",
                event_type="ms_teams_channels",
                raw_data={
                    "response": [
                        {
                            "id": "MICROSOFT_TEAMS-001",
                            "name": "Microsoft Teams workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MICROSOFT_TEAMS-002",
                            "name": "Microsoft Teams workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MICROSOFT_TEAMS-003",
                            "name": "Microsoft Teams workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MICROSOFT_TEAMS-004",
                            "name": "Microsoft Teams workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="microsoft_teams",
                source_type=SourceType.COLLABORATION,
                provider="microsoft_teams",
                event_type="ms_teams_security_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "MICROSOFT_TEAMS-001",
                            "name": "Microsoft Teams workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MICROSOFT_TEAMS-002",
                            "name": "Microsoft Teams workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MICROSOFT_TEAMS-003",
                            "name": "Microsoft Teams workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MICROSOFT_TEAMS-004",
                            "name": "Microsoft Teams workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Miro
# ---------------------------------------------------------------------------
class DemoMiroConnector(BaseConnector):
    """Simulates Miro collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="miro",
            source_type=SourceType.COLLABORATION,
            provider="miro",
        )

        result.events.append(
            RawEventData(
                source="miro",
                source_type=SourceType.COLLABORATION,
                provider="miro",
                event_type="miro_boards",
                raw_data={
                    "response": [
                        {
                            "id": "MIRO-001",
                            "name": "Miro workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MIRO-002",
                            "name": "Miro workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MIRO-003",
                            "name": "Miro workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MIRO-004",
                            "name": "Miro workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="miro",
                source_type=SourceType.COLLABORATION,
                provider="miro",
                event_type="miro_members",
                raw_data={
                    "response": [
                        {
                            "id": "MIRO-001",
                            "name": "Miro workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MIRO-002",
                            "name": "Miro workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MIRO-003",
                            "name": "Miro workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MIRO-004",
                            "name": "Miro workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Webex
# ---------------------------------------------------------------------------
class DemoWebexConnector(BaseConnector):
    """Simulates Webex collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="webex",
            source_type=SourceType.COMMUNICATION,
            provider="webex",
        )

        result.events.append(
            RawEventData(
                source="webex",
                source_type=SourceType.COMMUNICATION,
                provider="webex",
                event_type="webex_people",
                raw_data={
                    "response": [
                        {
                            "id": "WEBEX-001",
                            "name": "Webex channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WEBEX-002",
                            "name": "Webex channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WEBEX-003",
                            "name": "Webex channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WEBEX-004",
                            "name": "Webex channel 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="webex",
                source_type=SourceType.COMMUNICATION,
                provider="webex",
                event_type="webex_rooms",
                raw_data={
                    "response": [
                        {
                            "id": "WEBEX-001",
                            "name": "Webex channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WEBEX-002",
                            "name": "Webex channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WEBEX-003",
                            "name": "Webex channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="webex",
                source_type=SourceType.COMMUNICATION,
                provider="webex",
                event_type="webex_events",
                raw_data={
                    "response": [
                        {
                            "id": "WEBEX-001",
                            "name": "Webex channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WEBEX-002",
                            "name": "Webex channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WEBEX-003",
                            "name": "Webex channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WEBEX-004",
                            "name": "Webex channel 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# RingCentral
# ---------------------------------------------------------------------------
class DemoRingCentralConnector(BaseConnector):
    """Simulates RingCentral collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ringcentral",
            source_type=SourceType.COMMUNICATION,
            provider="ringcentral",
        )

        result.events.append(
            RawEventData(
                source="ringcentral",
                source_type=SourceType.COMMUNICATION,
                provider="ringcentral",
                event_type="ringcentral_extensions",
                raw_data={
                    "response": [
                        {
                            "id": "RINGCENTRAL-001",
                            "name": "RingCentral channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RINGCENTRAL-002",
                            "name": "RingCentral channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RINGCENTRAL-003",
                            "name": "RingCentral channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "RINGCENTRAL-004",
                            "name": "RingCentral channel 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ringcentral",
                source_type=SourceType.COMMUNICATION,
                provider="ringcentral",
                event_type="ringcentral_call_log",
                raw_data={
                    "response": [
                        {
                            "id": "RINGCENTRAL-001",
                            "name": "RingCentral channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RINGCENTRAL-002",
                            "name": "RingCentral channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RINGCENTRAL-003",
                            "name": "RingCentral channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Aircall
# ---------------------------------------------------------------------------
class DemoAircallConnector(BaseConnector):
    """Simulates Aircall collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aircall",
            source_type=SourceType.COMMUNICATION,
            provider="aircall",
        )

        result.events.append(
            RawEventData(
                source="aircall",
                source_type=SourceType.COMMUNICATION,
                provider="aircall",
                event_type="aircall_users",
                raw_data={
                    "response": [
                        {
                            "id": "AIRCALL-001",
                            "name": "Aircall channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AIRCALL-002",
                            "name": "Aircall channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AIRCALL-003",
                            "name": "Aircall channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AIRCALL-004",
                            "name": "Aircall channel 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aircall",
                source_type=SourceType.COMMUNICATION,
                provider="aircall",
                event_type="aircall_calls",
                raw_data={
                    "response": [
                        {
                            "id": "AIRCALL-001",
                            "name": "Aircall channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AIRCALL-002",
                            "name": "Aircall channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AIRCALL-003",
                            "name": "Aircall channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Dialpad
# ---------------------------------------------------------------------------
class DemoDialpadConnector(BaseConnector):
    """Simulates Dialpad collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="dialpad",
            source_type=SourceType.COMMUNICATION,
            provider="dialpad",
        )

        result.events.append(
            RawEventData(
                source="dialpad",
                source_type=SourceType.COMMUNICATION,
                provider="dialpad",
                event_type="dialpad_users",
                raw_data={
                    "response": [
                        {
                            "id": "DIALPAD-001",
                            "name": "Dialpad channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DIALPAD-002",
                            "name": "Dialpad channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DIALPAD-003",
                            "name": "Dialpad channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DIALPAD-004",
                            "name": "Dialpad channel 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dialpad",
                source_type=SourceType.COMMUNICATION,
                provider="dialpad",
                event_type="dialpad_call_logs",
                raw_data={
                    "response": [
                        {
                            "id": "DIALPAD-001",
                            "name": "Dialpad channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DIALPAD-002",
                            "name": "Dialpad channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DIALPAD-003",
                            "name": "Dialpad channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# 8x8
# ---------------------------------------------------------------------------
class DemoEightByEightConnector(BaseConnector):
    """Simulates 8x8 collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="eight_x_eight",
            source_type=SourceType.COMMUNICATION,
            provider="eight_x_eight",
        )

        result.events.append(
            RawEventData(
                source="eight_x_eight",
                source_type=SourceType.COMMUNICATION,
                provider="eight_x_eight",
                event_type="eight_x_eight_users",
                raw_data={
                    "response": [
                        {
                            "id": "EIGHT_X_EIGHT-001",
                            "name": "8x8 channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EIGHT_X_EIGHT-002",
                            "name": "8x8 channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EIGHT_X_EIGHT-003",
                            "name": "8x8 channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "EIGHT_X_EIGHT-004",
                            "name": "8x8 channel 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="eight_x_eight",
                source_type=SourceType.COMMUNICATION,
                provider="eight_x_eight",
                event_type="eight_x_eight_calls",
                raw_data={
                    "response": [
                        {
                            "id": "EIGHT_X_EIGHT-001",
                            "name": "8x8 channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EIGHT_X_EIGHT-002",
                            "name": "8x8 channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EIGHT_X_EIGHT-003",
                            "name": "8x8 channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Twilio
# ---------------------------------------------------------------------------
class DemoTwilioConnector(BaseConnector):
    """Simulates Twilio collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="twilio",
            source_type=SourceType.COMMUNICATION,
            provider="twilio",
        )

        result.events.append(
            RawEventData(
                source="twilio",
                source_type=SourceType.COMMUNICATION,
                provider="twilio",
                event_type="twilio_calls",
                raw_data={
                    "response": [
                        {
                            "id": "TWILIO-001",
                            "name": "Twilio channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TWILIO-002",
                            "name": "Twilio channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TWILIO-003",
                            "name": "Twilio channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TWILIO-004",
                            "name": "Twilio channel 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="twilio",
                source_type=SourceType.COMMUNICATION,
                provider="twilio",
                event_type="twilio_messages",
                raw_data={
                    "response": [
                        {
                            "id": "TWILIO-001",
                            "name": "Twilio channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TWILIO-002",
                            "name": "Twilio channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TWILIO-003",
                            "name": "Twilio channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="twilio",
                source_type=SourceType.COMMUNICATION,
                provider="twilio",
                event_type="twilio_api_keys",
                raw_data={
                    "response": [
                        {
                            "id": "TWILIO-001",
                            "name": "Twilio channel 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TWILIO-002",
                            "name": "Twilio channel 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TWILIO-003",
                            "name": "Twilio channel 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TWILIO-004",
                            "name": "Twilio channel 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Box
# ---------------------------------------------------------------------------
class DemoBoxConnector(BaseConnector):
    """Simulates Box collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="box",
            source_type=SourceType.FILE_STORAGE,
            provider="box",
        )

        result.events.append(
            RawEventData(
                source="box",
                source_type=SourceType.FILE_STORAGE,
                provider="box",
                event_type="box_users",
                raw_data={
                    "response": [
                        {
                            "id": "BOX-001",
                            "name": "Box file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BOX-002",
                            "name": "Box file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BOX-003",
                            "name": "Box file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BOX-004",
                            "name": "Box file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="box",
                source_type=SourceType.FILE_STORAGE,
                provider="box",
                event_type="box_root_items",
                raw_data={
                    "response": [
                        {
                            "id": "BOX-001",
                            "name": "Box file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BOX-002",
                            "name": "Box file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BOX-003",
                            "name": "Box file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BOX-004",
                            "name": "Box file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="box",
                source_type=SourceType.FILE_STORAGE,
                provider="box",
                event_type="box_events",
                raw_data={
                    "response": [
                        {
                            "id": "BOX-001",
                            "name": "Box file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BOX-002",
                            "name": "Box file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BOX-003",
                            "name": "Box file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BOX-004",
                            "name": "Box file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Dropbox
# ---------------------------------------------------------------------------
class DemoDropboxConnector(BaseConnector):
    """Simulates Dropbox collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="dropbox",
            source_type=SourceType.FILE_STORAGE,
            provider="dropbox",
        )

        result.events.append(
            RawEventData(
                source="dropbox",
                source_type=SourceType.FILE_STORAGE,
                provider="dropbox",
                event_type="dropbox_members",
                raw_data={
                    "response": [
                        {
                            "id": "DROPBOX-001",
                            "name": "Dropbox file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DROPBOX-002",
                            "name": "Dropbox file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DROPBOX-003",
                            "name": "Dropbox file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DROPBOX-004",
                            "name": "Dropbox file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dropbox",
                source_type=SourceType.FILE_STORAGE,
                provider="dropbox",
                event_type="dropbox_events",
                raw_data={
                    "response": [
                        {
                            "id": "DROPBOX-001",
                            "name": "Dropbox file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DROPBOX-002",
                            "name": "Dropbox file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DROPBOX-003",
                            "name": "Dropbox file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DROPBOX-004",
                            "name": "Dropbox file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Google Drive
# ---------------------------------------------------------------------------
class DemoGoogleDriveConnector(BaseConnector):
    """Simulates Google Drive collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="google_drive",
            source_type=SourceType.FILE_STORAGE,
            provider="google_drive",
        )

        result.events.append(
            RawEventData(
                source="google_drive",
                source_type=SourceType.FILE_STORAGE,
                provider="google_drive",
                event_type="google_drive_files",
                raw_data={
                    "response": [
                        {
                            "id": "GOOGLE_DRIVE-001",
                            "name": "Google Drive file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GOOGLE_DRIVE-002",
                            "name": "Google Drive file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GOOGLE_DRIVE-003",
                            "name": "Google Drive file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GOOGLE_DRIVE-004",
                            "name": "Google Drive file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="google_drive",
                source_type=SourceType.FILE_STORAGE,
                provider="google_drive",
                event_type="google_drive_shared_drives",
                raw_data={
                    "response": [
                        {
                            "id": "GOOGLE_DRIVE-001",
                            "name": "Google Drive file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GOOGLE_DRIVE-002",
                            "name": "Google Drive file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GOOGLE_DRIVE-003",
                            "name": "Google Drive file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GOOGLE_DRIVE-004",
                            "name": "Google Drive file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="google_drive",
                source_type=SourceType.FILE_STORAGE,
                provider="google_drive",
                event_type="google_drive_about",
                raw_data={
                    "response": [
                        {
                            "id": "GOOGLE_DRIVE-001",
                            "name": "Google Drive file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "GOOGLE_DRIVE-002",
                            "name": "Google Drive file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "GOOGLE_DRIVE-003",
                            "name": "Google Drive file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "GOOGLE_DRIVE-004",
                            "name": "Google Drive file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Egnyte
# ---------------------------------------------------------------------------
class DemoEgnyteConnector(BaseConnector):
    """Simulates Egnyte collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="egnyte",
            source_type=SourceType.FILE_STORAGE,
            provider="egnyte",
        )

        result.events.append(
            RawEventData(
                source="egnyte",
                source_type=SourceType.FILE_STORAGE,
                provider="egnyte",
                event_type="egnyte_users",
                raw_data={
                    "response": [
                        {
                            "id": "EGNYTE-001",
                            "name": "Egnyte file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EGNYTE-002",
                            "name": "Egnyte file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EGNYTE-003",
                            "name": "Egnyte file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "EGNYTE-004",
                            "name": "Egnyte file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="egnyte",
                source_type=SourceType.FILE_STORAGE,
                provider="egnyte",
                event_type="egnyte_files",
                raw_data={
                    "response": [
                        {
                            "id": "EGNYTE-001",
                            "name": "Egnyte file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EGNYTE-002",
                            "name": "Egnyte file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EGNYTE-003",
                            "name": "Egnyte file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "EGNYTE-004",
                            "name": "Egnyte file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="egnyte",
                source_type=SourceType.FILE_STORAGE,
                provider="egnyte",
                event_type="egnyte_audit",
                raw_data={
                    "response": [
                        {
                            "id": "EGNYTE-001",
                            "name": "Egnyte file 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "EGNYTE-002",
                            "name": "Egnyte file 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "EGNYTE-003",
                            "name": "Egnyte file 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "EGNYTE-004",
                            "name": "Egnyte file 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Ramp
# ---------------------------------------------------------------------------
class DemoRampConnector(BaseConnector):
    """Simulates Ramp collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ramp",
            source_type=SourceType.FINANCE,
            provider="ramp",
        )

        result.events.append(
            RawEventData(
                source="ramp",
                source_type=SourceType.FINANCE,
                provider="ramp",
                event_type="ramp_users",
                raw_data={
                    "response": [
                        {
                            "id": "RAMP-001",
                            "name": "Ramp transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RAMP-002",
                            "name": "Ramp transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RAMP-003",
                            "name": "Ramp transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "RAMP-004",
                            "name": "Ramp transaction 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ramp",
                source_type=SourceType.FINANCE,
                provider="ramp",
                event_type="ramp_transactions",
                raw_data={
                    "response": [
                        {
                            "id": "RAMP-001",
                            "name": "Ramp transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RAMP-002",
                            "name": "Ramp transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RAMP-003",
                            "name": "Ramp transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ramp",
                source_type=SourceType.FINANCE,
                provider="ramp",
                event_type="ramp_cards",
                raw_data={
                    "response": [
                        {
                            "id": "RAMP-001",
                            "name": "Ramp transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RAMP-002",
                            "name": "Ramp transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RAMP-003",
                            "name": "Ramp transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "RAMP-004",
                            "name": "Ramp transaction 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Brex
# ---------------------------------------------------------------------------
class DemoBrexConnector(BaseConnector):
    """Simulates Brex collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="brex",
            source_type=SourceType.FINANCE,
            provider="brex",
        )

        result.events.append(
            RawEventData(
                source="brex",
                source_type=SourceType.FINANCE,
                provider="brex",
                event_type="brex_users",
                raw_data={
                    "response": [
                        {
                            "id": "BREX-001",
                            "name": "Brex transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BREX-002",
                            "name": "Brex transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BREX-003",
                            "name": "Brex transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BREX-004",
                            "name": "Brex transaction 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="brex",
                source_type=SourceType.FINANCE,
                provider="brex",
                event_type="brex_transactions",
                raw_data={
                    "response": [
                        {
                            "id": "BREX-001",
                            "name": "Brex transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BREX-002",
                            "name": "Brex transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BREX-003",
                            "name": "Brex transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="brex",
                source_type=SourceType.FINANCE,
                provider="brex",
                event_type="brex_cards",
                raw_data={
                    "response": [
                        {
                            "id": "BREX-001",
                            "name": "Brex transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BREX-002",
                            "name": "Brex transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BREX-003",
                            "name": "Brex transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BREX-004",
                            "name": "Brex transaction 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# NetSuite
# ---------------------------------------------------------------------------
class DemoNetSuiteConnector(BaseConnector):
    """Simulates NetSuite collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="netsuite",
            source_type=SourceType.FINANCE,
            provider="netsuite",
        )

        result.events.append(
            RawEventData(
                source="netsuite",
                source_type=SourceType.FINANCE,
                provider="netsuite",
                event_type="netsuite_employees",
                raw_data={
                    "response": [
                        {
                            "id": "NETSUITE-001",
                            "name": "NetSuite transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NETSUITE-002",
                            "name": "NetSuite transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NETSUITE-003",
                            "name": "NetSuite transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NETSUITE-004",
                            "name": "NetSuite transaction 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="netsuite",
                source_type=SourceType.FINANCE,
                provider="netsuite",
                event_type="netsuite_vendors",
                raw_data={
                    "response": [
                        {
                            "id": "NETSUITE-001",
                            "name": "NetSuite transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NETSUITE-002",
                            "name": "NetSuite transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NETSUITE-003",
                            "name": "NetSuite transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="netsuite",
                source_type=SourceType.FINANCE,
                provider="netsuite",
                event_type="netsuite_purchase_orders",
                raw_data={
                    "response": [
                        {
                            "id": "NETSUITE-001",
                            "name": "NetSuite transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NETSUITE-002",
                            "name": "NetSuite transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NETSUITE-003",
                            "name": "NetSuite transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NETSUITE-004",
                            "name": "NetSuite transaction 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Vendr
# ---------------------------------------------------------------------------
class DemoVendrConnector(BaseConnector):
    """Simulates Vendr collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="vendr",
            source_type=SourceType.FINANCE,
            provider="vendr",
        )

        result.events.append(
            RawEventData(
                source="vendr",
                source_type=SourceType.FINANCE,
                provider="vendr",
                event_type="vendr_contracts",
                raw_data={
                    "response": [
                        {
                            "id": "VENDR-001",
                            "name": "Vendr transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "VENDR-002",
                            "name": "Vendr transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "VENDR-003",
                            "name": "Vendr transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "VENDR-004",
                            "name": "Vendr transaction 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vendr",
                source_type=SourceType.FINANCE,
                provider="vendr",
                event_type="vendr_vendors",
                raw_data={
                    "response": [
                        {
                            "id": "VENDR-001",
                            "name": "Vendr transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "VENDR-002",
                            "name": "Vendr transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "VENDR-003",
                            "name": "Vendr transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vendr",
                source_type=SourceType.FINANCE,
                provider="vendr",
                event_type="vendr_renewals",
                raw_data={
                    "response": [
                        {
                            "id": "VENDR-001",
                            "name": "Vendr transaction 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "VENDR-002",
                            "name": "Vendr transaction 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "VENDR-003",
                            "name": "Vendr transaction 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "VENDR-004",
                            "name": "Vendr transaction 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# DocuSign
# ---------------------------------------------------------------------------
class DemoDocuSignConnector(BaseConnector):
    """Simulates DocuSign collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="docusign",
            source_type=SourceType.LEGAL,
            provider="docusign",
        )

        result.events.append(
            RawEventData(
                source="docusign",
                source_type=SourceType.LEGAL,
                provider="docusign",
                event_type="docusign_envelopes",
                raw_data={
                    "response": [
                        {
                            "id": "DOCUSIGN-001",
                            "name": "DocuSign document 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOCUSIGN-002",
                            "name": "DocuSign document 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOCUSIGN-003",
                            "name": "DocuSign document 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOCUSIGN-004",
                            "name": "DocuSign document 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="docusign",
                source_type=SourceType.LEGAL,
                provider="docusign",
                event_type="docusign_users",
                raw_data={
                    "response": [
                        {
                            "id": "DOCUSIGN-001",
                            "name": "DocuSign document 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOCUSIGN-002",
                            "name": "DocuSign document 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOCUSIGN-003",
                            "name": "DocuSign document 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOCUSIGN-004",
                            "name": "DocuSign document 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Ironclad
# ---------------------------------------------------------------------------
class DemoIroncladConnector(BaseConnector):
    """Simulates Ironclad collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ironclad",
            source_type=SourceType.LEGAL,
            provider="ironclad",
        )

        result.events.append(
            RawEventData(
                source="ironclad",
                source_type=SourceType.LEGAL,
                provider="ironclad",
                event_type="ironclad_workflows",
                raw_data={
                    "response": [
                        {
                            "id": "IRONCLAD-001",
                            "name": "Ironclad document 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "IRONCLAD-002",
                            "name": "Ironclad document 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "IRONCLAD-003",
                            "name": "Ironclad document 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "IRONCLAD-004",
                            "name": "Ironclad document 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ironclad",
                source_type=SourceType.LEGAL,
                provider="ironclad",
                event_type="ironclad_records",
                raw_data={
                    "response": [
                        {
                            "id": "IRONCLAD-001",
                            "name": "Ironclad document 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "IRONCLAD-002",
                            "name": "Ironclad document 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "IRONCLAD-003",
                            "name": "Ironclad document 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "IRONCLAD-004",
                            "name": "Ironclad document 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Dropbox Sign
# ---------------------------------------------------------------------------
class DemoDropboxSignConnector(BaseConnector):
    """Simulates Dropbox Sign collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="dropbox_sign",
            source_type=SourceType.LEGAL,
            provider="dropbox_sign",
        )

        result.events.append(
            RawEventData(
                source="dropbox_sign",
                source_type=SourceType.LEGAL,
                provider="dropbox_sign",
                event_type="dropbox_sign_requests",
                raw_data={
                    "response": [
                        {
                            "id": "DROPBOX_SIGN-001",
                            "name": "Dropbox Sign document 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DROPBOX_SIGN-002",
                            "name": "Dropbox Sign document 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DROPBOX_SIGN-003",
                            "name": "Dropbox Sign document 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DROPBOX_SIGN-004",
                            "name": "Dropbox Sign document 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="dropbox_sign",
                source_type=SourceType.LEGAL,
                provider="dropbox_sign",
                event_type="dropbox_sign_account",
                raw_data={
                    "response": [
                        {
                            "id": "DROPBOX_SIGN-001",
                            "name": "Dropbox Sign document 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DROPBOX_SIGN-002",
                            "name": "Dropbox Sign document 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DROPBOX_SIGN-003",
                            "name": "Dropbox Sign document 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DROPBOX_SIGN-004",
                            "name": "Dropbox Sign document 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Segment
# ---------------------------------------------------------------------------
class DemoSegmentConnector(BaseConnector):
    """Simulates Segment collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="segment",
            source_type=SourceType.ANALYTICS,
            provider="segment",
        )

        result.events.append(
            RawEventData(
                source="segment",
                source_type=SourceType.ANALYTICS,
                provider="segment",
                event_type="segment_sources",
                raw_data={
                    "response": [
                        {
                            "id": "SEGMENT-001",
                            "name": "Segment dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SEGMENT-002",
                            "name": "Segment dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SEGMENT-003",
                            "name": "Segment dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SEGMENT-004",
                            "name": "Segment dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="segment",
                source_type=SourceType.ANALYTICS,
                provider="segment",
                event_type="segment_destinations",
                raw_data={
                    "response": [
                        {
                            "id": "SEGMENT-001",
                            "name": "Segment dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SEGMENT-002",
                            "name": "Segment dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SEGMENT-003",
                            "name": "Segment dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SEGMENT-004",
                            "name": "Segment dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="segment",
                source_type=SourceType.ANALYTICS,
                provider="segment",
                event_type="segment_tracking_plans",
                raw_data={
                    "response": [
                        {
                            "id": "SEGMENT-001",
                            "name": "Segment dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SEGMENT-002",
                            "name": "Segment dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SEGMENT-003",
                            "name": "Segment dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SEGMENT-004",
                            "name": "Segment dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Mixpanel
# ---------------------------------------------------------------------------
class DemoMixpanelConnector(BaseConnector):
    """Simulates Mixpanel collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="mixpanel",
            source_type=SourceType.ANALYTICS,
            provider="mixpanel",
        )

        result.events.append(
            RawEventData(
                source="mixpanel",
                source_type=SourceType.ANALYTICS,
                provider="mixpanel",
                event_type="mixpanel_users",
                raw_data={
                    "response": [
                        {
                            "id": "MIXPANEL-001",
                            "name": "Mixpanel dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MIXPANEL-002",
                            "name": "Mixpanel dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MIXPANEL-003",
                            "name": "Mixpanel dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MIXPANEL-004",
                            "name": "Mixpanel dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="mixpanel",
                source_type=SourceType.ANALYTICS,
                provider="mixpanel",
                event_type="mixpanel_events",
                raw_data={
                    "response": [
                        {
                            "id": "MIXPANEL-001",
                            "name": "Mixpanel dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MIXPANEL-002",
                            "name": "Mixpanel dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MIXPANEL-003",
                            "name": "Mixpanel dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MIXPANEL-004",
                            "name": "Mixpanel dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Tableau
# ---------------------------------------------------------------------------
class DemoTableauConnector(BaseConnector):
    """Simulates Tableau collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="tableau",
            source_type=SourceType.ANALYTICS,
            provider="tableau",
        )

        result.events.append(
            RawEventData(
                source="tableau",
                source_type=SourceType.ANALYTICS,
                provider="tableau",
                event_type="tableau_users",
                raw_data={
                    "response": [
                        {
                            "id": "TABLEAU-001",
                            "name": "Tableau dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TABLEAU-002",
                            "name": "Tableau dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TABLEAU-003",
                            "name": "Tableau dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TABLEAU-004",
                            "name": "Tableau dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="tableau",
                source_type=SourceType.ANALYTICS,
                provider="tableau",
                event_type="tableau_workbooks",
                raw_data={
                    "response": [
                        {
                            "id": "TABLEAU-001",
                            "name": "Tableau dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TABLEAU-002",
                            "name": "Tableau dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TABLEAU-003",
                            "name": "Tableau dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TABLEAU-004",
                            "name": "Tableau dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Domo
# ---------------------------------------------------------------------------
class DemoDomoConnector(BaseConnector):
    """Simulates Domo collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="domo",
            source_type=SourceType.ANALYTICS,
            provider="domo",
        )

        result.events.append(
            RawEventData(
                source="domo",
                source_type=SourceType.ANALYTICS,
                provider="domo",
                event_type="domo_datasets",
                raw_data={
                    "response": [
                        {
                            "id": "DOMO-001",
                            "name": "Domo dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOMO-002",
                            "name": "Domo dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOMO-003",
                            "name": "Domo dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOMO-004",
                            "name": "Domo dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="domo",
                source_type=SourceType.ANALYTICS,
                provider="domo",
                event_type="domo_users",
                raw_data={
                    "response": [
                        {
                            "id": "DOMO-001",
                            "name": "Domo dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "DOMO-002",
                            "name": "Domo dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "DOMO-003",
                            "name": "Domo dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "DOMO-004",
                            "name": "Domo dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Qlik
# ---------------------------------------------------------------------------
class DemoQlikConnector(BaseConnector):
    """Simulates Qlik collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="qlik",
            source_type=SourceType.ANALYTICS,
            provider="qlik",
        )

        result.events.append(
            RawEventData(
                source="qlik",
                source_type=SourceType.ANALYTICS,
                provider="qlik",
                event_type="qlik_apps",
                raw_data={
                    "response": [
                        {
                            "id": "QLIK-001",
                            "name": "Qlik dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "QLIK-002",
                            "name": "Qlik dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "QLIK-003",
                            "name": "Qlik dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "QLIK-004",
                            "name": "Qlik dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="qlik",
                source_type=SourceType.ANALYTICS,
                provider="qlik",
                event_type="qlik_users",
                raw_data={
                    "response": [
                        {
                            "id": "QLIK-001",
                            "name": "Qlik dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "QLIK-002",
                            "name": "Qlik dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "QLIK-003",
                            "name": "Qlik dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "QLIK-004",
                            "name": "Qlik dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="qlik",
                source_type=SourceType.ANALYTICS,
                provider="qlik",
                event_type="qlik_spaces",
                raw_data={
                    "response": [
                        {
                            "id": "QLIK-001",
                            "name": "Qlik dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "QLIK-002",
                            "name": "Qlik dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "QLIK-003",
                            "name": "Qlik dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "QLIK-004",
                            "name": "Qlik dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Sigma Computing
# ---------------------------------------------------------------------------
class DemoSigmaComputingConnector(BaseConnector):
    """Simulates Sigma Computing collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sigma_computing",
            source_type=SourceType.ANALYTICS,
            provider="sigma_computing",
        )

        result.events.append(
            RawEventData(
                source="sigma_computing",
                source_type=SourceType.ANALYTICS,
                provider="sigma_computing",
                event_type="sigma_workbooks",
                raw_data={
                    "response": [
                        {
                            "id": "SIGMA_COMPUTING-001",
                            "name": "Sigma Computing dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SIGMA_COMPUTING-002",
                            "name": "Sigma Computing dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SIGMA_COMPUTING-003",
                            "name": "Sigma Computing dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SIGMA_COMPUTING-004",
                            "name": "Sigma Computing dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sigma_computing",
                source_type=SourceType.ANALYTICS,
                provider="sigma_computing",
                event_type="sigma_members",
                raw_data={
                    "response": [
                        {
                            "id": "SIGMA_COMPUTING-001",
                            "name": "Sigma Computing dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SIGMA_COMPUTING-002",
                            "name": "Sigma Computing dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SIGMA_COMPUTING-003",
                            "name": "Sigma Computing dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SIGMA_COMPUTING-004",
                            "name": "Sigma Computing dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Transcend
# ---------------------------------------------------------------------------
class DemoTranscendConnector(BaseConnector):
    """Simulates Transcend collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="transcend",
            source_type=SourceType.GRC,
            provider="transcend",
        )

        result.events.append(
            RawEventData(
                source="transcend",
                source_type=SourceType.GRC,
                provider="transcend",
                event_type="transcend_data_silos",
                raw_data={
                    "response": [
                        {
                            "id": "TRANSCEND-001",
                            "name": "Transcend control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRANSCEND-002",
                            "name": "Transcend control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRANSCEND-003",
                            "name": "Transcend control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TRANSCEND-004",
                            "name": "Transcend control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="transcend",
                source_type=SourceType.GRC,
                provider="transcend",
                event_type="transcend_requests",
                raw_data={
                    "response": [
                        {
                            "id": "TRANSCEND-001",
                            "name": "Transcend control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRANSCEND-002",
                            "name": "Transcend control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRANSCEND-003",
                            "name": "Transcend control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TRANSCEND-004",
                            "name": "Transcend control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="transcend",
                source_type=SourceType.GRC,
                provider="transcend",
                event_type="transcend_data_flows",
                raw_data={
                    "response": [
                        {
                            "id": "TRANSCEND-001",
                            "name": "Transcend control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TRANSCEND-002",
                            "name": "Transcend control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TRANSCEND-003",
                            "name": "Transcend control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TRANSCEND-004",
                            "name": "Transcend control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Ketch
# ---------------------------------------------------------------------------
class DemoKetchConnector(BaseConnector):
    """Simulates Ketch collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="ketch",
            source_type=SourceType.GRC,
            provider="ketch",
        )

        result.events.append(
            RawEventData(
                source="ketch",
                source_type=SourceType.GRC,
                provider="ketch",
                event_type="ketch_policies",
                raw_data={
                    "response": [
                        {
                            "id": "KETCH-001",
                            "name": "Ketch control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KETCH-002",
                            "name": "Ketch control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KETCH-003",
                            "name": "Ketch control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KETCH-004",
                            "name": "Ketch control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ketch",
                source_type=SourceType.GRC,
                provider="ketch",
                event_type="ketch_consent",
                raw_data={
                    "response": [
                        {
                            "id": "KETCH-001",
                            "name": "Ketch control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KETCH-002",
                            "name": "Ketch control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KETCH-003",
                            "name": "Ketch control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KETCH-004",
                            "name": "Ketch control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="ketch",
                source_type=SourceType.GRC,
                provider="ketch",
                event_type="ketch_data_subjects",
                raw_data={
                    "response": [
                        {
                            "id": "KETCH-001",
                            "name": "Ketch control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "KETCH-002",
                            "name": "Ketch control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "KETCH-003",
                            "name": "Ketch control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "KETCH-004",
                            "name": "Ketch control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------
class DemoOpenAIPlatformConnector(BaseConnector):
    """Simulates OpenAI collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="openai_platform",
            source_type=SourceType.AI_ML,
            provider="openai_platform",
        )

        result.events.append(
            RawEventData(
                source="openai_platform",
                source_type=SourceType.AI_ML,
                provider="openai_platform",
                event_type="openai_models",
                raw_data={
                    "response": [
                        {
                            "id": "OPENAI_PLATFORM-001",
                            "name": "OpenAI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OPENAI_PLATFORM-002",
                            "name": "OpenAI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OPENAI_PLATFORM-003",
                            "name": "OpenAI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "OPENAI_PLATFORM-004",
                            "name": "OpenAI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="openai_platform",
                source_type=SourceType.AI_ML,
                provider="openai_platform",
                event_type="openai_usage",
                raw_data={
                    "response": [
                        {
                            "id": "OPENAI_PLATFORM-001",
                            "name": "OpenAI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OPENAI_PLATFORM-002",
                            "name": "OpenAI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OPENAI_PLATFORM-003",
                            "name": "OpenAI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "OPENAI_PLATFORM-004",
                            "name": "OpenAI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="openai_platform",
                source_type=SourceType.AI_ML,
                provider="openai_platform",
                event_type="openai_assistants",
                raw_data={
                    "response": [
                        {
                            "id": "OPENAI_PLATFORM-001",
                            "name": "OpenAI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OPENAI_PLATFORM-002",
                            "name": "OpenAI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OPENAI_PLATFORM-003",
                            "name": "OpenAI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "OPENAI_PLATFORM-004",
                            "name": "OpenAI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------
class DemoAnthropicPlatformConnector(BaseConnector):
    """Simulates Anthropic collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="anthropic_platform",
            source_type=SourceType.AI_ML,
            provider="anthropic_platform",
        )

        result.events.append(
            RawEventData(
                source="anthropic_platform",
                source_type=SourceType.AI_ML,
                provider="anthropic_platform",
                event_type="anthropic_models",
                raw_data={
                    "response": [
                        {
                            "id": "ANTHROPIC_PLATFORM-001",
                            "name": "Anthropic model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ANTHROPIC_PLATFORM-002",
                            "name": "Anthropic model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ANTHROPIC_PLATFORM-003",
                            "name": "Anthropic model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ANTHROPIC_PLATFORM-004",
                            "name": "Anthropic model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="anthropic_platform",
                source_type=SourceType.AI_ML,
                provider="anthropic_platform",
                event_type="anthropic_usage",
                raw_data={
                    "response": [
                        {
                            "id": "ANTHROPIC_PLATFORM-001",
                            "name": "Anthropic model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ANTHROPIC_PLATFORM-002",
                            "name": "Anthropic model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ANTHROPIC_PLATFORM-003",
                            "name": "Anthropic model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ANTHROPIC_PLATFORM-004",
                            "name": "Anthropic model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# AWS Bedrock
# ---------------------------------------------------------------------------
class DemoAWSBedrockConnector(BaseConnector):
    """Simulates AWS Bedrock collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="aws_bedrock",
            source_type=SourceType.AI_ML,
            provider="aws_bedrock",
        )

        result.events.append(
            RawEventData(
                source="aws_bedrock",
                source_type=SourceType.AI_ML,
                provider="aws_bedrock",
                event_type="bedrock_models",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_BEDROCK-001",
                            "name": "AWS Bedrock model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_BEDROCK-002",
                            "name": "AWS Bedrock model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_BEDROCK-003",
                            "name": "AWS Bedrock model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AWS_BEDROCK-004",
                            "name": "AWS Bedrock model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aws_bedrock",
                source_type=SourceType.AI_ML,
                provider="aws_bedrock",
                event_type="bedrock_invocation_logs",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_BEDROCK-001",
                            "name": "AWS Bedrock model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_BEDROCK-002",
                            "name": "AWS Bedrock model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_BEDROCK-003",
                            "name": "AWS Bedrock model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AWS_BEDROCK-004",
                            "name": "AWS Bedrock model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="aws_bedrock",
                source_type=SourceType.AI_ML,
                provider="aws_bedrock",
                event_type="bedrock_guardrails",
                raw_data={
                    "response": [
                        {
                            "id": "AWS_BEDROCK-001",
                            "name": "AWS Bedrock model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "AWS_BEDROCK-002",
                            "name": "AWS Bedrock model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "AWS_BEDROCK-003",
                            "name": "AWS Bedrock model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "AWS_BEDROCK-004",
                            "name": "AWS Bedrock model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Credo AI
# ---------------------------------------------------------------------------
class DemoCredoAIConnector(BaseConnector):
    """Simulates Credo AI collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="credo_ai",
            source_type=SourceType.AI_GOVERNANCE,
            provider="credo_ai",
        )

        result.events.append(
            RawEventData(
                source="credo_ai",
                source_type=SourceType.AI_GOVERNANCE,
                provider="credo_ai",
                event_type="credo_models",
                raw_data={
                    "response": [
                        {
                            "id": "CREDO_AI-001",
                            "name": "Credo AI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CREDO_AI-002",
                            "name": "Credo AI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CREDO_AI-003",
                            "name": "Credo AI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CREDO_AI-004",
                            "name": "Credo AI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="credo_ai",
                source_type=SourceType.AI_GOVERNANCE,
                provider="credo_ai",
                event_type="credo_assessments",
                raw_data={
                    "response": [
                        {
                            "id": "CREDO_AI-001",
                            "name": "Credo AI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CREDO_AI-002",
                            "name": "Credo AI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CREDO_AI-003",
                            "name": "Credo AI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CREDO_AI-004",
                            "name": "Credo AI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="credo_ai",
                source_type=SourceType.AI_GOVERNANCE,
                provider="credo_ai",
                event_type="credo_policies",
                raw_data={
                    "response": [
                        {
                            "id": "CREDO_AI-001",
                            "name": "Credo AI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CREDO_AI-002",
                            "name": "Credo AI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CREDO_AI-003",
                            "name": "Credo AI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CREDO_AI-004",
                            "name": "Credo AI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Arthur AI
# ---------------------------------------------------------------------------
class DemoArthurAIConnector(BaseConnector):
    """Simulates Arthur AI collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="arthur_ai",
            source_type=SourceType.AI_GOVERNANCE,
            provider="arthur_ai",
        )

        result.events.append(
            RawEventData(
                source="arthur_ai",
                source_type=SourceType.AI_GOVERNANCE,
                provider="arthur_ai",
                event_type="arthur_models",
                raw_data={
                    "response": [
                        {
                            "id": "ARTHUR_AI-001",
                            "name": "Arthur AI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ARTHUR_AI-002",
                            "name": "Arthur AI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ARTHUR_AI-003",
                            "name": "Arthur AI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ARTHUR_AI-004",
                            "name": "Arthur AI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="arthur_ai",
                source_type=SourceType.AI_GOVERNANCE,
                provider="arthur_ai",
                event_type="arthur_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "ARTHUR_AI-001",
                            "name": "Arthur AI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ARTHUR_AI-002",
                            "name": "Arthur AI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ARTHUR_AI-003",
                            "name": "Arthur AI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ARTHUR_AI-004",
                            "name": "Arthur AI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="arthur_ai",
                source_type=SourceType.AI_GOVERNANCE,
                provider="arthur_ai",
                event_type="arthur_inferences",
                raw_data={
                    "response": [
                        {
                            "id": "ARTHUR_AI-001",
                            "name": "Arthur AI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ARTHUR_AI-002",
                            "name": "Arthur AI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ARTHUR_AI-003",
                            "name": "Arthur AI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ARTHUR_AI-004",
                            "name": "Arthur AI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Fiddler AI
# ---------------------------------------------------------------------------
class DemoFiddlerAIConnector(BaseConnector):
    """Simulates Fiddler AI collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="fiddler_ai",
            source_type=SourceType.AI_GOVERNANCE,
            provider="fiddler_ai",
        )

        result.events.append(
            RawEventData(
                source="fiddler_ai",
                source_type=SourceType.AI_GOVERNANCE,
                provider="fiddler_ai",
                event_type="fiddler_models",
                raw_data={
                    "response": [
                        {
                            "id": "FIDDLER_AI-001",
                            "name": "Fiddler AI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIDDLER_AI-002",
                            "name": "Fiddler AI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIDDLER_AI-003",
                            "name": "Fiddler AI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FIDDLER_AI-004",
                            "name": "Fiddler AI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fiddler_ai",
                source_type=SourceType.AI_GOVERNANCE,
                provider="fiddler_ai",
                event_type="fiddler_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "FIDDLER_AI-001",
                            "name": "Fiddler AI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIDDLER_AI-002",
                            "name": "Fiddler AI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIDDLER_AI-003",
                            "name": "Fiddler AI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FIDDLER_AI-004",
                            "name": "Fiddler AI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="fiddler_ai",
                source_type=SourceType.AI_GOVERNANCE,
                provider="fiddler_ai",
                event_type="fiddler_monitoring",
                raw_data={
                    "response": [
                        {
                            "id": "FIDDLER_AI-001",
                            "name": "Fiddler AI model 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIDDLER_AI-002",
                            "name": "Fiddler AI model 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIDDLER_AI-003",
                            "name": "Fiddler AI model 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FIDDLER_AI-004",
                            "name": "Fiddler AI model 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# AppOmni
# ---------------------------------------------------------------------------
class DemoAppOmniConnector(BaseConnector):
    """Simulates AppOmni collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="appomni",
            source_type=SourceType.SSPM,
            provider="appomni",
        )

        result.events.append(
            RawEventData(
                source="appomni",
                source_type=SourceType.SSPM,
                provider="appomni",
                event_type="appomni_applications",
                raw_data={
                    "response": [
                        {
                            "id": "APPOMNI-001",
                            "name": "AppOmni application 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "APPOMNI-002",
                            "name": "AppOmni application 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "APPOMNI-003",
                            "name": "AppOmni application 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "APPOMNI-004",
                            "name": "AppOmni application 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="appomni",
                source_type=SourceType.SSPM,
                provider="appomni",
                event_type="appomni_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "APPOMNI-001",
                            "name": "AppOmni application 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "APPOMNI-002",
                            "name": "AppOmni application 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "APPOMNI-003",
                            "name": "AppOmni application 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "APPOMNI-004",
                            "name": "AppOmni application 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="appomni",
                source_type=SourceType.SSPM,
                provider="appomni",
                event_type="appomni_policies",
                raw_data={
                    "response": [
                        {
                            "id": "APPOMNI-001",
                            "name": "AppOmni application 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "APPOMNI-002",
                            "name": "AppOmni application 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "APPOMNI-003",
                            "name": "AppOmni application 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "APPOMNI-004",
                            "name": "AppOmni application 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Obsidian Security
# ---------------------------------------------------------------------------
class DemoObsidianSecurityConnector(BaseConnector):
    """Simulates Obsidian Security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="obsidian_security",
            source_type=SourceType.SSPM,
            provider="obsidian_security",
        )

        result.events.append(
            RawEventData(
                source="obsidian_security",
                source_type=SourceType.SSPM,
                provider="obsidian_security",
                event_type="obsidian_applications",
                raw_data={
                    "response": [
                        {
                            "id": "OBSIDIAN_SECURITY-001",
                            "name": "Obsidian Security application 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OBSIDIAN_SECURITY-002",
                            "name": "Obsidian Security application 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OBSIDIAN_SECURITY-003",
                            "name": "Obsidian Security application 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "OBSIDIAN_SECURITY-004",
                            "name": "Obsidian Security application 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="obsidian_security",
                source_type=SourceType.SSPM,
                provider="obsidian_security",
                event_type="obsidian_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "OBSIDIAN_SECURITY-001",
                            "name": "Obsidian Security application 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OBSIDIAN_SECURITY-002",
                            "name": "Obsidian Security application 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OBSIDIAN_SECURITY-003",
                            "name": "Obsidian Security application 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "OBSIDIAN_SECURITY-004",
                            "name": "Obsidian Security application 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Nudge Security
# ---------------------------------------------------------------------------
class DemoNudgeSecurityConnector(BaseConnector):
    """Simulates Nudge Security collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="nudge_security",
            source_type=SourceType.SSPM,
            provider="nudge_security",
        )

        result.events.append(
            RawEventData(
                source="nudge_security",
                source_type=SourceType.SSPM,
                provider="nudge_security",
                event_type="nudge_applications",
                raw_data={
                    "response": [
                        {
                            "id": "NUDGE_SECURITY-001",
                            "name": "Nudge Security application 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NUDGE_SECURITY-002",
                            "name": "Nudge Security application 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NUDGE_SECURITY-003",
                            "name": "Nudge Security application 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NUDGE_SECURITY-004",
                            "name": "Nudge Security application 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="nudge_security",
                source_type=SourceType.SSPM,
                provider="nudge_security",
                event_type="nudge_identities",
                raw_data={
                    "response": [
                        {
                            "id": "NUDGE_SECURITY-001",
                            "name": "Nudge Security application 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NUDGE_SECURITY-002",
                            "name": "Nudge Security application 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NUDGE_SECURITY-003",
                            "name": "Nudge Security application 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NUDGE_SECURITY-004",
                            "name": "Nudge Security application 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="nudge_security",
                source_type=SourceType.SSPM,
                provider="nudge_security",
                event_type="nudge_risks",
                raw_data={
                    "response": [
                        {
                            "id": "NUDGE_SECURITY-001",
                            "name": "Nudge Security application 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "NUDGE_SECURITY-002",
                            "name": "Nudge Security application 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "NUDGE_SECURITY-003",
                            "name": "Nudge Security application 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "NUDGE_SECURITY-004",
                            "name": "Nudge Security application 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Rootly
# ---------------------------------------------------------------------------
class DemoRootlyConnector(BaseConnector):
    """Simulates Rootly collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="rootly",
            source_type=SourceType.INCIDENT_MGMT,
            provider="rootly",
        )

        result.events.append(
            RawEventData(
                source="rootly",
                source_type=SourceType.INCIDENT_MGMT,
                provider="rootly",
                event_type="rootly_incidents",
                raw_data={
                    "response": [
                        {
                            "id": "ROOTLY-001",
                            "name": "Rootly incident 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ROOTLY-002",
                            "name": "Rootly incident 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ROOTLY-003",
                            "name": "Rootly incident 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rootly",
                source_type=SourceType.INCIDENT_MGMT,
                provider="rootly",
                event_type="rootly_services",
                raw_data={
                    "response": [
                        {
                            "id": "ROOTLY-001",
                            "name": "Rootly incident 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ROOTLY-002",
                            "name": "Rootly incident 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ROOTLY-003",
                            "name": "Rootly incident 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ROOTLY-004",
                            "name": "Rootly incident 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="rootly",
                source_type=SourceType.INCIDENT_MGMT,
                provider="rootly",
                event_type="rootly_post_mortems",
                raw_data={
                    "response": [
                        {
                            "id": "ROOTLY-001",
                            "name": "Rootly incident 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ROOTLY-002",
                            "name": "Rootly incident 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ROOTLY-003",
                            "name": "Rootly incident 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# incident.io
# ---------------------------------------------------------------------------
class DemoIncidentIOConnector(BaseConnector):
    """Simulates incident.io collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="incident_io",
            source_type=SourceType.INCIDENT_MGMT,
            provider="incident_io",
        )

        result.events.append(
            RawEventData(
                source="incident_io",
                source_type=SourceType.INCIDENT_MGMT,
                provider="incident_io",
                event_type="incidentio_incidents",
                raw_data={
                    "response": [
                        {
                            "id": "INCIDENT_IO-001",
                            "name": "incident.io incident 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INCIDENT_IO-002",
                            "name": "incident.io incident 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INCIDENT_IO-003",
                            "name": "incident.io incident 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="incident_io",
                source_type=SourceType.INCIDENT_MGMT,
                provider="incident_io",
                event_type="incidentio_actions",
                raw_data={
                    "response": [
                        {
                            "id": "INCIDENT_IO-001",
                            "name": "incident.io incident 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INCIDENT_IO-002",
                            "name": "incident.io incident 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INCIDENT_IO-003",
                            "name": "incident.io incident 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "INCIDENT_IO-004",
                            "name": "incident.io incident 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="incident_io",
                source_type=SourceType.INCIDENT_MGMT,
                provider="incident_io",
                event_type="incidentio_roles",
                raw_data={
                    "response": [
                        {
                            "id": "INCIDENT_IO-001",
                            "name": "incident.io incident 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "INCIDENT_IO-002",
                            "name": "incident.io incident 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "INCIDENT_IO-003",
                            "name": "incident.io incident 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# FireHydrant
# ---------------------------------------------------------------------------
class DemoFireHydrantConnector(BaseConnector):
    """Simulates FireHydrant collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="firehydrant",
            source_type=SourceType.INCIDENT_MGMT,
            provider="firehydrant",
        )

        result.events.append(
            RawEventData(
                source="firehydrant",
                source_type=SourceType.INCIDENT_MGMT,
                provider="firehydrant",
                event_type="firehydrant_incidents",
                raw_data={
                    "response": [
                        {
                            "id": "FIREHYDRANT-001",
                            "name": "FireHydrant incident 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIREHYDRANT-002",
                            "name": "FireHydrant incident 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIREHYDRANT-003",
                            "name": "FireHydrant incident 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="firehydrant",
                source_type=SourceType.INCIDENT_MGMT,
                provider="firehydrant",
                event_type="firehydrant_services",
                raw_data={
                    "response": [
                        {
                            "id": "FIREHYDRANT-001",
                            "name": "FireHydrant incident 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIREHYDRANT-002",
                            "name": "FireHydrant incident 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIREHYDRANT-003",
                            "name": "FireHydrant incident 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "FIREHYDRANT-004",
                            "name": "FireHydrant incident 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="firehydrant",
                source_type=SourceType.INCIDENT_MGMT,
                provider="firehydrant",
                event_type="firehydrant_runbooks",
                raw_data={
                    "response": [
                        {
                            "id": "FIREHYDRANT-001",
                            "name": "FireHydrant incident 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "FIREHYDRANT-002",
                            "name": "FireHydrant incident 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "FIREHYDRANT-003",
                            "name": "FireHydrant incident 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Snipe-IT
# ---------------------------------------------------------------------------
class DemoSnipeITConnector(BaseConnector):
    """Simulates Snipe-IT collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="snipe_it",
            source_type=SourceType.ITAM,
            provider="snipe_it",
        )

        result.events.append(
            RawEventData(
                source="snipe_it",
                source_type=SourceType.ITAM,
                provider="snipe_it",
                event_type="snipeit_hardware",
                raw_data={
                    "response": [
                        {
                            "id": "SNIPE_IT-001",
                            "name": "Snipe-IT asset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SNIPE_IT-002",
                            "name": "Snipe-IT asset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SNIPE_IT-003",
                            "name": "Snipe-IT asset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SNIPE_IT-004",
                            "name": "Snipe-IT asset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="snipe_it",
                source_type=SourceType.ITAM,
                provider="snipe_it",
                event_type="snipeit_licenses",
                raw_data={
                    "response": [
                        {
                            "id": "SNIPE_IT-001",
                            "name": "Snipe-IT asset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SNIPE_IT-002",
                            "name": "Snipe-IT asset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SNIPE_IT-003",
                            "name": "Snipe-IT asset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SNIPE_IT-004",
                            "name": "Snipe-IT asset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="snipe_it",
                source_type=SourceType.ITAM,
                provider="snipe_it",
                event_type="snipeit_users",
                raw_data={
                    "response": [
                        {
                            "id": "SNIPE_IT-001",
                            "name": "Snipe-IT asset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SNIPE_IT-002",
                            "name": "Snipe-IT asset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SNIPE_IT-003",
                            "name": "Snipe-IT asset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SNIPE_IT-004",
                            "name": "Snipe-IT asset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Oomnitza
# ---------------------------------------------------------------------------
class DemoOomnitzaConnector(BaseConnector):
    """Simulates Oomnitza collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="oomnitza",
            source_type=SourceType.ITAM,
            provider="oomnitza",
        )

        result.events.append(
            RawEventData(
                source="oomnitza",
                source_type=SourceType.ITAM,
                provider="oomnitza",
                event_type="oomnitza_assets",
                raw_data={
                    "response": [
                        {
                            "id": "OOMNITZA-001",
                            "name": "Oomnitza asset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OOMNITZA-002",
                            "name": "Oomnitza asset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OOMNITZA-003",
                            "name": "Oomnitza asset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "OOMNITZA-004",
                            "name": "Oomnitza asset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="oomnitza",
                source_type=SourceType.ITAM,
                provider="oomnitza",
                event_type="oomnitza_users",
                raw_data={
                    "response": [
                        {
                            "id": "OOMNITZA-001",
                            "name": "Oomnitza asset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OOMNITZA-002",
                            "name": "Oomnitza asset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OOMNITZA-003",
                            "name": "Oomnitza asset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "OOMNITZA-004",
                            "name": "Oomnitza asset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="oomnitza",
                source_type=SourceType.ITAM,
                provider="oomnitza",
                event_type="oomnitza_software",
                raw_data={
                    "response": [
                        {
                            "id": "OOMNITZA-001",
                            "name": "Oomnitza asset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OOMNITZA-002",
                            "name": "Oomnitza asset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OOMNITZA-003",
                            "name": "Oomnitza asset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "OOMNITZA-004",
                            "name": "Oomnitza asset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# ServiceNow ITAM
# ---------------------------------------------------------------------------
class DemoServiceNowITAMConnector(BaseConnector):
    """Simulates ServiceNow ITAM collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="servicenow_itam",
            source_type=SourceType.ITAM,
            provider="servicenow_itam",
        )

        result.events.append(
            RawEventData(
                source="servicenow_itam",
                source_type=SourceType.ITAM,
                provider="servicenow_itam",
                event_type="sn_itam_hardware",
                raw_data={
                    "response": [
                        {
                            "id": "SERVICENOW_ITAM-001",
                            "name": "ServiceNow ITAM asset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SERVICENOW_ITAM-002",
                            "name": "ServiceNow ITAM asset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SERVICENOW_ITAM-003",
                            "name": "ServiceNow ITAM asset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SERVICENOW_ITAM-004",
                            "name": "ServiceNow ITAM asset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="servicenow_itam",
                source_type=SourceType.ITAM,
                provider="servicenow_itam",
                event_type="sn_itam_licenses",
                raw_data={
                    "response": [
                        {
                            "id": "SERVICENOW_ITAM-001",
                            "name": "ServiceNow ITAM asset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SERVICENOW_ITAM-002",
                            "name": "ServiceNow ITAM asset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SERVICENOW_ITAM-003",
                            "name": "ServiceNow ITAM asset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SERVICENOW_ITAM-004",
                            "name": "ServiceNow ITAM asset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="servicenow_itam",
                source_type=SourceType.ITAM,
                provider="servicenow_itam",
                event_type="sn_itam_ci",
                raw_data={
                    "response": [
                        {
                            "id": "SERVICENOW_ITAM-001",
                            "name": "ServiceNow ITAM asset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SERVICENOW_ITAM-002",
                            "name": "ServiceNow ITAM asset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SERVICENOW_ITAM-003",
                            "name": "ServiceNow ITAM asset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SERVICENOW_ITAM-004",
                            "name": "ServiceNow ITAM asset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Monte Carlo
# ---------------------------------------------------------------------------
class DemoMonteCarloConnector(BaseConnector):
    """Simulates Monte Carlo collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="monte_carlo",
            source_type=SourceType.DATA_OBSERVABILITY,
            provider="monte_carlo",
        )

        result.events.append(
            RawEventData(
                source="monte_carlo",
                source_type=SourceType.DATA_OBSERVABILITY,
                provider="monte_carlo",
                event_type="montecarlo_tables",
                raw_data={
                    "response": [
                        {
                            "id": "MONTE_CARLO-001",
                            "name": "Monte Carlo table 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MONTE_CARLO-002",
                            "name": "Monte Carlo table 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MONTE_CARLO-003",
                            "name": "Monte Carlo table 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="monte_carlo",
                source_type=SourceType.DATA_OBSERVABILITY,
                provider="monte_carlo",
                event_type="montecarlo_incidents",
                raw_data={
                    "response": [
                        {
                            "id": "MONTE_CARLO-001",
                            "name": "Monte Carlo table 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MONTE_CARLO-002",
                            "name": "Monte Carlo table 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MONTE_CARLO-003",
                            "name": "Monte Carlo table 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "MONTE_CARLO-004",
                            "name": "Monte Carlo table 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="monte_carlo",
                source_type=SourceType.DATA_OBSERVABILITY,
                provider="monte_carlo",
                event_type="montecarlo_monitors",
                raw_data={
                    "response": [
                        {
                            "id": "MONTE_CARLO-001",
                            "name": "Monte Carlo table 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "MONTE_CARLO-002",
                            "name": "Monte Carlo table 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "MONTE_CARLO-003",
                            "name": "Monte Carlo table 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Bigeye
# ---------------------------------------------------------------------------
class DemoBigeyeConnector(BaseConnector):
    """Simulates Bigeye collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="bigeye",
            source_type=SourceType.DATA_OBSERVABILITY,
            provider="bigeye",
        )

        result.events.append(
            RawEventData(
                source="bigeye",
                source_type=SourceType.DATA_OBSERVABILITY,
                provider="bigeye",
                event_type="bigeye_metrics",
                raw_data={
                    "response": [
                        {
                            "id": "BIGEYE-001",
                            "name": "Bigeye table 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BIGEYE-002",
                            "name": "Bigeye table 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BIGEYE-003",
                            "name": "Bigeye table 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="bigeye",
                source_type=SourceType.DATA_OBSERVABILITY,
                provider="bigeye",
                event_type="bigeye_alerts",
                raw_data={
                    "response": [
                        {
                            "id": "BIGEYE-001",
                            "name": "Bigeye table 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BIGEYE-002",
                            "name": "Bigeye table 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BIGEYE-003",
                            "name": "Bigeye table 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BIGEYE-004",
                            "name": "Bigeye table 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Vantage
# ---------------------------------------------------------------------------
class DemoVantageFinOpsConnector(BaseConnector):
    """Simulates Vantage collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="vantage_finops",
            source_type=SourceType.FINOPS,
            provider="vantage_finops",
        )

        result.events.append(
            RawEventData(
                source="vantage_finops",
                source_type=SourceType.FINOPS,
                provider="vantage_finops",
                event_type="vantage_costs",
                raw_data={
                    "response": [
                        {
                            "id": "VANTAGE_FINOPS-001",
                            "name": "Vantage cost_report 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "VANTAGE_FINOPS-002",
                            "name": "Vantage cost_report 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "VANTAGE_FINOPS-003",
                            "name": "Vantage cost_report 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "VANTAGE_FINOPS-004",
                            "name": "Vantage cost_report 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vantage_finops",
                source_type=SourceType.FINOPS,
                provider="vantage_finops",
                event_type="vantage_cost_reports",
                raw_data={
                    "response": [
                        {
                            "id": "VANTAGE_FINOPS-001",
                            "name": "Vantage cost_report 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "VANTAGE_FINOPS-002",
                            "name": "Vantage cost_report 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "VANTAGE_FINOPS-003",
                            "name": "Vantage cost_report 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="vantage_finops",
                source_type=SourceType.FINOPS,
                provider="vantage_finops",
                event_type="vantage_providers",
                raw_data={
                    "response": [
                        {
                            "id": "VANTAGE_FINOPS-001",
                            "name": "Vantage cost_report 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "VANTAGE_FINOPS-002",
                            "name": "Vantage cost_report 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "VANTAGE_FINOPS-003",
                            "name": "Vantage cost_report 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "VANTAGE_FINOPS-004",
                            "name": "Vantage cost_report 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# CloudHealth
# ---------------------------------------------------------------------------
class DemoCloudHealthConnector(BaseConnector):
    """Simulates CloudHealth collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cloudhealth",
            source_type=SourceType.FINOPS,
            provider="cloudhealth",
        )

        result.events.append(
            RawEventData(
                source="cloudhealth",
                source_type=SourceType.FINOPS,
                provider="cloudhealth",
                event_type="cloudhealth_accounts",
                raw_data={
                    "response": [
                        {
                            "id": "CLOUDHEALTH-001",
                            "name": "CloudHealth cost_report 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CLOUDHEALTH-002",
                            "name": "CloudHealth cost_report 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CLOUDHEALTH-003",
                            "name": "CloudHealth cost_report 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CLOUDHEALTH-004",
                            "name": "CloudHealth cost_report 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cloudhealth",
                source_type=SourceType.FINOPS,
                provider="cloudhealth",
                event_type="cloudhealth_cost",
                raw_data={
                    "response": [
                        {
                            "id": "CLOUDHEALTH-001",
                            "name": "CloudHealth cost_report 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CLOUDHEALTH-002",
                            "name": "CloudHealth cost_report 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CLOUDHEALTH-003",
                            "name": "CloudHealth cost_report 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cloudhealth",
                source_type=SourceType.FINOPS,
                provider="cloudhealth",
                event_type="cloudhealth_olap",
                raw_data={
                    "response": [
                        {
                            "id": "CLOUDHEALTH-001",
                            "name": "CloudHealth cost_report 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CLOUDHEALTH-002",
                            "name": "CloudHealth cost_report 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CLOUDHEALTH-003",
                            "name": "CloudHealth cost_report 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CLOUDHEALTH-004",
                            "name": "CloudHealth cost_report 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Spot by NetApp
# ---------------------------------------------------------------------------
class DemoSpotNetAppConnector(BaseConnector):
    """Simulates Spot by NetApp collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="spot_netapp",
            source_type=SourceType.FINOPS,
            provider="spot_netapp",
        )

        result.events.append(
            RawEventData(
                source="spot_netapp",
                source_type=SourceType.FINOPS,
                provider="spot_netapp",
                event_type="spot_groups",
                raw_data={
                    "response": [
                        {
                            "id": "SPOT_NETAPP-001",
                            "name": "Spot by NetApp cost_report 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SPOT_NETAPP-002",
                            "name": "Spot by NetApp cost_report 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SPOT_NETAPP-003",
                            "name": "Spot by NetApp cost_report 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SPOT_NETAPP-004",
                            "name": "Spot by NetApp cost_report 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="spot_netapp",
                source_type=SourceType.FINOPS,
                provider="spot_netapp",
                event_type="spot_ocean_clusters",
                raw_data={
                    "response": [
                        {
                            "id": "SPOT_NETAPP-001",
                            "name": "Spot by NetApp cost_report 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SPOT_NETAPP-002",
                            "name": "Spot by NetApp cost_report 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SPOT_NETAPP-003",
                            "name": "Spot by NetApp cost_report 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="spot_netapp",
                source_type=SourceType.FINOPS,
                provider="spot_netapp",
                event_type="spot_events",
                raw_data={
                    "response": [
                        {
                            "id": "SPOT_NETAPP-001",
                            "name": "Spot by NetApp cost_report 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SPOT_NETAPP-002",
                            "name": "Spot by NetApp cost_report 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SPOT_NETAPP-003",
                            "name": "Spot by NetApp cost_report 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SPOT_NETAPP-004",
                            "name": "Spot by NetApp cost_report 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Zentry
# ---------------------------------------------------------------------------
class DemoZentryConnector(BaseConnector):
    """Simulates Zentry collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="zentry",
            source_type=SourceType.IAM,
            provider="zentry",
        )

        result.events.append(
            RawEventData(
                source="zentry",
                source_type=SourceType.IAM,
                provider="zentry",
                event_type="zentry_users",
                raw_data={
                    "response": [
                        {
                            "id": "ZENTRY-001",
                            "name": "Zentry account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZENTRY-002",
                            "name": "Zentry account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZENTRY-003",
                            "name": "Zentry account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ZENTRY-004",
                            "name": "Zentry account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="zentry",
                source_type=SourceType.IAM,
                provider="zentry",
                event_type="zentry_connections",
                raw_data={
                    "response": [
                        {
                            "id": "ZENTRY-001",
                            "name": "Zentry account 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ZENTRY-002",
                            "name": "Zentry account 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ZENTRY-003",
                            "name": "Zentry account 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ZENTRY-004",
                            "name": "Zentry account 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# OpenVPN
# ---------------------------------------------------------------------------
class DemoOpenVPNConnector(BaseConnector):
    """Simulates OpenVPN collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="openvpn",
            source_type=SourceType.NETWORK,
            provider="openvpn",
        )

        result.events.append(
            RawEventData(
                source="openvpn",
                source_type=SourceType.NETWORK,
                provider="openvpn",
                event_type="openvpn_networks",
                raw_data={
                    "response": [
                        {
                            "id": "OPENVPN-001",
                            "name": "OpenVPN device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OPENVPN-002",
                            "name": "OpenVPN device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OPENVPN-003",
                            "name": "OpenVPN device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="openvpn",
                source_type=SourceType.NETWORK,
                provider="openvpn",
                event_type="openvpn_connectors",
                raw_data={
                    "response": [
                        {
                            "id": "OPENVPN-001",
                            "name": "OpenVPN device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OPENVPN-002",
                            "name": "OpenVPN device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OPENVPN-003",
                            "name": "OpenVPN device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "OPENVPN-004",
                            "name": "OpenVPN device 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="openvpn",
                source_type=SourceType.NETWORK,
                provider="openvpn",
                event_type="openvpn_users",
                raw_data={
                    "response": [
                        {
                            "id": "OPENVPN-001",
                            "name": "OpenVPN device 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "OPENVPN-002",
                            "name": "OpenVPN device 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "OPENVPN-003",
                            "name": "OpenVPN device 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# TeamViewer
# ---------------------------------------------------------------------------
class DemoTeamViewerConnector(BaseConnector):
    """Simulates TeamViewer collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="teamviewer",
            source_type=SourceType.COLLABORATION,
            provider="teamviewer",
        )

        result.events.append(
            RawEventData(
                source="teamviewer",
                source_type=SourceType.COLLABORATION,
                provider="teamviewer",
                event_type="teamviewer_devices",
                raw_data={
                    "response": [
                        {
                            "id": "TEAMVIEWER-001",
                            "name": "TeamViewer workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TEAMVIEWER-002",
                            "name": "TeamViewer workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TEAMVIEWER-003",
                            "name": "TeamViewer workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TEAMVIEWER-004",
                            "name": "TeamViewer workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="teamviewer",
                source_type=SourceType.COLLABORATION,
                provider="teamviewer",
                event_type="teamviewer_users",
                raw_data={
                    "response": [
                        {
                            "id": "TEAMVIEWER-001",
                            "name": "TeamViewer workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TEAMVIEWER-002",
                            "name": "TeamViewer workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TEAMVIEWER-003",
                            "name": "TeamViewer workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TEAMVIEWER-004",
                            "name": "TeamViewer workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="teamviewer",
                source_type=SourceType.COLLABORATION,
                provider="teamviewer",
                event_type="teamviewer_sessions",
                raw_data={
                    "response": [
                        {
                            "id": "TEAMVIEWER-001",
                            "name": "TeamViewer workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "TEAMVIEWER-002",
                            "name": "TeamViewer workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "TEAMVIEWER-003",
                            "name": "TeamViewer workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "TEAMVIEWER-004",
                            "name": "TeamViewer workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Cyral
# ---------------------------------------------------------------------------
class DemoCyralConnector(BaseConnector):
    """Simulates Cyral collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="cyral",
            source_type=SourceType.DATA_GOVERNANCE,
            provider="cyral",
        )

        result.events.append(
            RawEventData(
                source="cyral",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="cyral",
                event_type="cyral_repos",
                raw_data={
                    "response": [
                        {
                            "id": "CYRAL-001",
                            "name": "Cyral dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CYRAL-002",
                            "name": "Cyral dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CYRAL-003",
                            "name": "Cyral dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CYRAL-004",
                            "name": "Cyral dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cyral",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="cyral",
                event_type="cyral_policies",
                raw_data={
                    "response": [
                        {
                            "id": "CYRAL-001",
                            "name": "Cyral dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CYRAL-002",
                            "name": "Cyral dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CYRAL-003",
                            "name": "Cyral dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CYRAL-004",
                            "name": "Cyral dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="cyral",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="cyral",
                event_type="cyral_activities",
                raw_data={
                    "response": [
                        {
                            "id": "CYRAL-001",
                            "name": "Cyral dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CYRAL-002",
                            "name": "Cyral dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CYRAL-003",
                            "name": "Cyral dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CYRAL-004",
                            "name": "Cyral dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Immuta
# ---------------------------------------------------------------------------
class DemoImmutaConnector(BaseConnector):
    """Simulates Immuta collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="immuta",
            source_type=SourceType.DATA_GOVERNANCE,
            provider="immuta",
        )

        result.events.append(
            RawEventData(
                source="immuta",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="immuta",
                event_type="immuta_data_sources",
                raw_data={
                    "response": [
                        {
                            "id": "IMMUTA-001",
                            "name": "Immuta dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "IMMUTA-002",
                            "name": "Immuta dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "IMMUTA-003",
                            "name": "Immuta dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "IMMUTA-004",
                            "name": "Immuta dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="immuta",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="immuta",
                event_type="immuta_policies",
                raw_data={
                    "response": [
                        {
                            "id": "IMMUTA-001",
                            "name": "Immuta dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "IMMUTA-002",
                            "name": "Immuta dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "IMMUTA-003",
                            "name": "Immuta dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "IMMUTA-004",
                            "name": "Immuta dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="immuta",
                source_type=SourceType.DATA_GOVERNANCE,
                provider="immuta",
                event_type="immuta_audit",
                raw_data={
                    "response": [
                        {
                            "id": "IMMUTA-001",
                            "name": "Immuta dataset 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "IMMUTA-002",
                            "name": "Immuta dataset 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "IMMUTA-003",
                            "name": "Immuta dataset 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "IMMUTA-004",
                            "name": "Immuta dataset 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Sprinto
# ---------------------------------------------------------------------------
class DemoSprintoConnector(BaseConnector):
    """Simulates Sprinto collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sprinto",
            source_type=SourceType.GRC,
            provider="sprinto",
        )

        result.events.append(
            RawEventData(
                source="sprinto",
                source_type=SourceType.GRC,
                provider="sprinto",
                event_type="sprinto_controls",
                raw_data={
                    "response": [
                        {
                            "id": "SPRINTO-001",
                            "name": "Sprinto control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SPRINTO-002",
                            "name": "Sprinto control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SPRINTO-003",
                            "name": "Sprinto control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SPRINTO-004",
                            "name": "Sprinto control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sprinto",
                source_type=SourceType.GRC,
                provider="sprinto",
                event_type="sprinto_evidence",
                raw_data={
                    "response": [
                        {
                            "id": "SPRINTO-001",
                            "name": "Sprinto control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SPRINTO-002",
                            "name": "Sprinto control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SPRINTO-003",
                            "name": "Sprinto control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SPRINTO-004",
                            "name": "Sprinto control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sprinto",
                source_type=SourceType.GRC,
                provider="sprinto",
                event_type="sprinto_policies",
                raw_data={
                    "response": [
                        {
                            "id": "SPRINTO-001",
                            "name": "Sprinto control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SPRINTO-002",
                            "name": "Sprinto control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SPRINTO-003",
                            "name": "Sprinto control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SPRINTO-004",
                            "name": "Sprinto control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Thoropass
# ---------------------------------------------------------------------------
class DemoThoropassConnector(BaseConnector):
    """Simulates Thoropass collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="thoropass",
            source_type=SourceType.GRC,
            provider="thoropass",
        )

        result.events.append(
            RawEventData(
                source="thoropass",
                source_type=SourceType.GRC,
                provider="thoropass",
                event_type="thoropass_controls",
                raw_data={
                    "response": [
                        {
                            "id": "THOROPASS-001",
                            "name": "Thoropass control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "THOROPASS-002",
                            "name": "Thoropass control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "THOROPASS-003",
                            "name": "Thoropass control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "THOROPASS-004",
                            "name": "Thoropass control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="thoropass",
                source_type=SourceType.GRC,
                provider="thoropass",
                event_type="thoropass_evidence",
                raw_data={
                    "response": [
                        {
                            "id": "THOROPASS-001",
                            "name": "Thoropass control 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "THOROPASS-002",
                            "name": "Thoropass control 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "THOROPASS-003",
                            "name": "Thoropass control 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "THOROPASS-004",
                            "name": "Thoropass control 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Backstage
# ---------------------------------------------------------------------------
class DemoBackstageConnector(BaseConnector):
    """Simulates Backstage collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="backstage",
            source_type=SourceType.INFRASTRUCTURE,
            provider="backstage",
        )

        result.events.append(
            RawEventData(
                source="backstage",
                source_type=SourceType.INFRASTRUCTURE,
                provider="backstage",
                event_type="backstage_entities",
                raw_data={
                    "response": [
                        {
                            "id": "BACKSTAGE-001",
                            "name": "Backstage resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BACKSTAGE-002",
                            "name": "Backstage resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BACKSTAGE-003",
                            "name": "Backstage resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BACKSTAGE-004",
                            "name": "Backstage resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="backstage",
                source_type=SourceType.INFRASTRUCTURE,
                provider="backstage",
                event_type="backstage_locations",
                raw_data={
                    "response": [
                        {
                            "id": "BACKSTAGE-001",
                            "name": "Backstage resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BACKSTAGE-002",
                            "name": "Backstage resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BACKSTAGE-003",
                            "name": "Backstage resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BACKSTAGE-004",
                            "name": "Backstage resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="backstage",
                source_type=SourceType.INFRASTRUCTURE,
                provider="backstage",
                event_type="backstage_techdocs",
                raw_data={
                    "response": [
                        {
                            "id": "BACKSTAGE-001",
                            "name": "Backstage resource 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "BACKSTAGE-002",
                            "name": "Backstage resource 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "BACKSTAGE-003",
                            "name": "Backstage resource 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "BACKSTAGE-004",
                            "name": "Backstage resource 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Retool
# ---------------------------------------------------------------------------
class DemoRetoolConnector(BaseConnector):
    """Simulates Retool collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="retool",
            source_type=SourceType.COLLABORATION,
            provider="retool",
        )

        result.events.append(
            RawEventData(
                source="retool",
                source_type=SourceType.COLLABORATION,
                provider="retool",
                event_type="retool_users",
                raw_data={
                    "response": [
                        {
                            "id": "RETOOL-001",
                            "name": "Retool workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RETOOL-002",
                            "name": "Retool workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RETOOL-003",
                            "name": "Retool workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "RETOOL-004",
                            "name": "Retool workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="retool",
                source_type=SourceType.COLLABORATION,
                provider="retool",
                event_type="retool_groups",
                raw_data={
                    "response": [
                        {
                            "id": "RETOOL-001",
                            "name": "Retool workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RETOOL-002",
                            "name": "Retool workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RETOOL-003",
                            "name": "Retool workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "RETOOL-004",
                            "name": "Retool workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="retool",
                source_type=SourceType.COLLABORATION,
                provider="retool",
                event_type="retool_apps",
                raw_data={
                    "response": [
                        {
                            "id": "RETOOL-001",
                            "name": "Retool workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "RETOOL-002",
                            "name": "Retool workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "RETOOL-003",
                            "name": "Retool workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "RETOOL-004",
                            "name": "Retool workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# SendGrid
# ---------------------------------------------------------------------------
class DemoSendGridConnector(BaseConnector):
    """Simulates SendGrid collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="sendgrid",
            source_type=SourceType.EMAIL,
            provider="sendgrid",
        )

        result.events.append(
            RawEventData(
                source="sendgrid",
                source_type=SourceType.EMAIL,
                provider="sendgrid",
                event_type="sendgrid_teammates",
                raw_data={
                    "response": [
                        {
                            "id": "SENDGRID-001",
                            "name": "SendGrid message 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SENDGRID-002",
                            "name": "SendGrid message 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SENDGRID-003",
                            "name": "SendGrid message 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sendgrid",
                source_type=SourceType.EMAIL,
                provider="sendgrid",
                event_type="sendgrid_api_keys",
                raw_data={
                    "response": [
                        {
                            "id": "SENDGRID-001",
                            "name": "SendGrid message 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SENDGRID-002",
                            "name": "SendGrid message 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SENDGRID-003",
                            "name": "SendGrid message 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "SENDGRID-004",
                            "name": "SendGrid message 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="sendgrid",
                source_type=SourceType.EMAIL,
                provider="sendgrid",
                event_type="sendgrid_bounces",
                raw_data={
                    "response": [
                        {
                            "id": "SENDGRID-001",
                            "name": "SendGrid message 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "SENDGRID-002",
                            "name": "SendGrid message 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "SENDGRID-003",
                            "name": "SendGrid message 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Envoy
# ---------------------------------------------------------------------------
class DemoEnvoyConnector(BaseConnector):
    """Simulates Envoy collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="envoy",
            source_type=SourceType.PHYSICAL,
            provider="envoy",
        )

        result.events.append(
            RawEventData(
                source="envoy",
                source_type=SourceType.PHYSICAL,
                provider="envoy",
                event_type="envoy_locations",
                raw_data={
                    "response": [
                        {
                            "id": "ENVOY-001",
                            "name": "Envoy location 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ENVOY-002",
                            "name": "Envoy location 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ENVOY-003",
                            "name": "Envoy location 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ENVOY-004",
                            "name": "Envoy location 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="envoy",
                source_type=SourceType.PHYSICAL,
                provider="envoy",
                event_type="envoy_visitors",
                raw_data={
                    "response": [
                        {
                            "id": "ENVOY-001",
                            "name": "Envoy location 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ENVOY-002",
                            "name": "Envoy location 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ENVOY-003",
                            "name": "Envoy location 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="envoy",
                source_type=SourceType.PHYSICAL,
                provider="envoy",
                event_type="envoy_employees",
                raw_data={
                    "response": [
                        {
                            "id": "ENVOY-001",
                            "name": "Envoy location 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "ENVOY-002",
                            "name": "Envoy location 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "ENVOY-003",
                            "name": "Envoy location 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "ENVOY-004",
                            "name": "Envoy location 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Canva
# ---------------------------------------------------------------------------
class DemoCanvaConnector(BaseConnector):
    """Simulates Canva collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="canva",
            source_type=SourceType.COLLABORATION,
            provider="canva",
        )

        result.events.append(
            RawEventData(
                source="canva",
                source_type=SourceType.COLLABORATION,
                provider="canva",
                event_type="canva_users",
                raw_data={
                    "response": [
                        {
                            "id": "CANVA-001",
                            "name": "Canva workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CANVA-002",
                            "name": "Canva workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CANVA-003",
                            "name": "Canva workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CANVA-004",
                            "name": "Canva workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="canva",
                source_type=SourceType.COLLABORATION,
                provider="canva",
                event_type="canva_designs",
                raw_data={
                    "response": [
                        {
                            "id": "CANVA-001",
                            "name": "Canva workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CANVA-002",
                            "name": "Canva workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CANVA-003",
                            "name": "Canva workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CANVA-004",
                            "name": "Canva workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# JetBrains
# ---------------------------------------------------------------------------
class DemoJetBrainsConnector(BaseConnector):
    """Simulates JetBrains collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="jetbrains",
            source_type=SourceType.CODE,
            provider="jetbrains",
        )

        result.events.append(
            RawEventData(
                source="jetbrains",
                source_type=SourceType.CODE,
                provider="jetbrains",
                event_type="jetbrains_users",
                raw_data={
                    "response": [
                        {
                            "id": "JETBRAINS-001",
                            "name": "JetBrains repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "JETBRAINS-002",
                            "name": "JetBrains repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "JETBRAINS-003",
                            "name": "JetBrains repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="jetbrains",
                source_type=SourceType.CODE,
                provider="jetbrains",
                event_type="jetbrains_projects",
                raw_data={
                    "response": [
                        {
                            "id": "JETBRAINS-001",
                            "name": "JetBrains repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "JETBRAINS-002",
                            "name": "JetBrains repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "JETBRAINS-003",
                            "name": "JetBrains repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "JETBRAINS-004",
                            "name": "JetBrains repo 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="jetbrains",
                source_type=SourceType.CODE,
                provider="jetbrains",
                event_type="jetbrains_permissions",
                raw_data={
                    "response": [
                        {
                            "id": "JETBRAINS-001",
                            "name": "JetBrains repo 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "JETBRAINS-002",
                            "name": "JetBrains repo 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "JETBRAINS-003",
                            "name": "JetBrains repo 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Webflow
# ---------------------------------------------------------------------------
class DemoWebflowConnector(BaseConnector):
    """Simulates Webflow collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="webflow",
            source_type=SourceType.COLLABORATION,
            provider="webflow",
        )

        result.events.append(
            RawEventData(
                source="webflow",
                source_type=SourceType.COLLABORATION,
                provider="webflow",
                event_type="webflow_sites",
                raw_data={
                    "response": [
                        {
                            "id": "WEBFLOW-001",
                            "name": "Webflow workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WEBFLOW-002",
                            "name": "Webflow workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WEBFLOW-003",
                            "name": "Webflow workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WEBFLOW-004",
                            "name": "Webflow workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="webflow",
                source_type=SourceType.COLLABORATION,
                provider="webflow",
                event_type="webflow_users",
                raw_data={
                    "response": [
                        {
                            "id": "WEBFLOW-001",
                            "name": "Webflow workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "WEBFLOW-002",
                            "name": "Webflow workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "WEBFLOW-003",
                            "name": "Webflow workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "WEBFLOW-004",
                            "name": "Webflow workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


# ---------------------------------------------------------------------------
# Contentful
# ---------------------------------------------------------------------------
class DemoContentfulConnector(BaseConnector):
    """Simulates Contentful collection."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="contentful",
            source_type=SourceType.COLLABORATION,
            provider="contentful",
        )

        result.events.append(
            RawEventData(
                source="contentful",
                source_type=SourceType.COLLABORATION,
                provider="contentful",
                event_type="contentful_spaces",
                raw_data={
                    "response": [
                        {
                            "id": "CONTENTFUL-001",
                            "name": "Contentful workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CONTENTFUL-002",
                            "name": "Contentful workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CONTENTFUL-003",
                            "name": "Contentful workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CONTENTFUL-004",
                            "name": "Contentful workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )
        result.events.append(
            RawEventData(
                source="contentful",
                source_type=SourceType.COLLABORATION,
                provider="contentful",
                event_type="contentful_users",
                raw_data={
                    "response": [
                        {
                            "id": "CONTENTFUL-001",
                            "name": "Contentful workspace 1",
                            "status": "inactive",
                            "created_at": (NOW - timedelta(days=10)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=3)).isoformat(),
                        },
                        {
                            "id": "CONTENTFUL-002",
                            "name": "Contentful workspace 2",
                            "status": "warning",
                            "created_at": (NOW - timedelta(days=20)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=6)).isoformat(),
                        },
                        {
                            "id": "CONTENTFUL-003",
                            "name": "Contentful workspace 3",
                            "status": "critical",
                            "created_at": (NOW - timedelta(days=30)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=9)).isoformat(),
                        },
                        {
                            "id": "CONTENTFUL-004",
                            "name": "Contentful workspace 4",
                            "status": "active",
                            "created_at": (NOW - timedelta(days=40)).isoformat(),
                            "updated_at": (NOW - timedelta(hours=12)).isoformat(),
                        },
                    ]
                },
            )
        )

        result.complete()
        return result


ALL_EXPANSION_CONNECTORS = [
    DemoHerokuConnector,
    DemoScalewayConnector,
    DemoRenderConnector,
    DemoNetlifyConnector,
    DemoVercelCloudConnector,
    DemoMongoDBAtlasConnector,
    DemoSupabaseConnector,
    DemoSnowflakeConnector,
    DemoAWSGovCloudConnector,
    DemoAWSInspectorConnector,
    DemoAkamaiConnector,
    DemoImpervaConnector,
    DemoPingIdentityNewConnector,
    DemoLastPassConnector,
    DemoDashlaneConnector,
    DemoNordPassConnector,
    DemoKeeperConnector,
    DemoAccessOwlConnector,
    DemoIndentConnector,
    DemoSaviyntConnector,
    DemoConductorOneConnector,
    DemoBoundaryConnector,
    DemoTeleportConnector,
    DemoStrongDMConnector,
    DemoDopplerConnector,
    DemoInfisicalConnector,
    DemoBitbucketConnector,
    DemoAWSCodeCommitConnector,
    DemoAzureReposConnector,
    DemoAzureDevOpsConnector,
    DemoArgoCDConnector,
    DemoHarnessConnector,
    DemoBuildkiteConnector,
    DemoLaunchDarklyConnector,
    DemoFivetranConnector,
    DemoDbtLabsConnector,
    DemoAsanaConnector,
    DemoLinearConnector,
    DemoClickUpConnector,
    DemoTrelloConnector,
    DemoMondayConnector,
    DemoShortcutConnector,
    DemoNotionConnector,
    DemoSmartsheetConnector,
    DemoWrikeConnector,
    DemoBasecampConnector,
    DemoHeightConnector,
    DemoFreshserviceConnector,
    DemoFreshdeskConnector,
    DemoZendeskConnector,
    DemoZohoDeskConnector,
    DemoHiBobConnector,
    DemoJustworksConnector,
    DemoLatticeConnector,
    DemoTriNetConnector,
    DemoDayforceConnector,
    DemoOracleHCMConnector,
    DemoPersonioConnector,
    DemoDeelConnector,
    DemoNamelyConnector,
    DemoPaychexFlexConnector,
    DemoHumaansConnector,
    DemoXeroPayrollConnector,
    DemoFifteenFiveConnector,
    DemoLeapsomeConnector,
    DemoHRCloudConnector,
    DemoISolvedConnector,
    DemoKenjoConnector,
    DemoEmploymentHeroConnector,
    DemoZohoPeopleConnector,
    DemoGreenhouseConnector,
    DemoLeverConnector,
    DemoAshbyConnector,
    DemoSmartRecruitersConnector,
    DemoTeamtailorConnector,
    DemoWorkableConnector,
    DemoCheckrConnector,
    DemoCertnConnector,
    DemoHireRightConnector,
    DemoSterlingConnector,
    DemoThree60LearningConnector,
    DemoCornerstoneConnector,
    DemoCourseraConnector,
    DemoEasyLlamaConnector,
    DemoInfosecIQConnector,
    DemoLinkedInLearningConnector,
    DemoTalentLMSConnector,
    DemoUdemyConnector,
    DemoDoceboConnector,
    DemoGO1Connector,
    DemoSoSafeConnector,
    DemoMoxsoConnector,
    DemoAwareGOConnector,
    DemoCyberReadyConnector,
    DemoHexnodeConnector,
    DemoNinjaOneConnector,
    DemoKolideConnector,
    DemoAddigyConnector,
    DemoMiradoreConnector,
    DemoAikidoConnector,
    DemoSonarCloudConnector,
    DemoWizCodeConnector,
    DemoHuntressConnector,
    DemoJitSecurityConnector,
    DemoUpwindConnector,
    DemoArnicaConnector,
    DemoPenteraConnector,
    DemoHorizon3Connector,
    DemoBugcrowdConnector,
    DemoIntigritiConnector,
    DemoHaloSecurityConnector,
    DemoTraceableAIConnector,
    DemoSentryConnector,
    DemoRollbarConnector,
    DemoDynatraceConnector,
    DemoSumoLogicNewConnector,
    DemoHubSpotConnector,
    DemoPipedriveConnector,
    DemoIntercomConnector,
    DemoGongConnector,
    DemoFreshsalesConnector,
    DemoAttioConnector,
    DemoCopperConnector,
    DemoCloseCRMConnector,
    DemoMicrosoftTeamsConnector,
    DemoMiroConnector,
    DemoWebexConnector,
    DemoRingCentralConnector,
    DemoAircallConnector,
    DemoDialpadConnector,
    DemoEightByEightConnector,
    DemoTwilioConnector,
    DemoBoxConnector,
    DemoDropboxConnector,
    DemoGoogleDriveConnector,
    DemoEgnyteConnector,
    DemoRampConnector,
    DemoBrexConnector,
    DemoNetSuiteConnector,
    DemoVendrConnector,
    DemoDocuSignConnector,
    DemoIroncladConnector,
    DemoDropboxSignConnector,
    DemoSegmentConnector,
    DemoMixpanelConnector,
    DemoTableauConnector,
    DemoDomoConnector,
    DemoQlikConnector,
    DemoSigmaComputingConnector,
    DemoTranscendConnector,
    DemoKetchConnector,
    DemoOpenAIPlatformConnector,
    DemoAnthropicPlatformConnector,
    DemoAWSBedrockConnector,
    DemoCredoAIConnector,
    DemoArthurAIConnector,
    DemoFiddlerAIConnector,
    DemoAppOmniConnector,
    DemoObsidianSecurityConnector,
    DemoNudgeSecurityConnector,
    DemoRootlyConnector,
    DemoIncidentIOConnector,
    DemoFireHydrantConnector,
    DemoSnipeITConnector,
    DemoOomnitzaConnector,
    DemoServiceNowITAMConnector,
    DemoMonteCarloConnector,
    DemoBigeyeConnector,
    DemoVantageFinOpsConnector,
    DemoCloudHealthConnector,
    DemoSpotNetAppConnector,
    DemoZentryConnector,
    DemoOpenVPNConnector,
    DemoTeamViewerConnector,
    DemoCyralConnector,
    DemoImmutaConnector,
    DemoSprintoConnector,
    DemoThoropassConnector,
    DemoBackstageConnector,
    DemoRetoolConnector,
    DemoSendGridConnector,
    DemoEnvoyConnector,
    DemoCanvaConnector,
    DemoJetBrainsConnector,
    DemoWebflowConnector,
    DemoContentfulConnector,
]
