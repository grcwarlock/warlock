# Warlock Product Documentation

Production documentation for the Warlock GRC platform. Updated as part of the QA gate.

## Technical

| Document | Description |
|----------|-------------|
| [Architecture](technical/architecture.md) | System architecture — 4-stage pipeline, storage, security model |
| [Data Model](technical/data-model.md) | 56-table schema, relationships, JSON columns, pipeline data flow |
| [Data Lake](technical/data-lake.md) | GRC Data Lake — 3 zones, 10 domains, DuckDB, Iceberg, RAG |
| [Security](technical/security.md) | Auth (JWT/API keys/MFA), ABAC, OPA, audit trail, GDPR |
| [Data map & subprocessors](technical/data-map-subprocessors.md) | DDQ/DPA-oriented data categories and typical subprocessors |
| [Data residency](technical/data-residency.md) | Regions, replicas, multi-tenancy vs geo, lake paths |
| [SAML roadmap](technical/saml-roadmap.md) | SAML SP — planning only (OIDC is implemented today) |

## Product

| Document | Description |
|----------|-------------|
| [Overview](product/overview.md) | What Warlock is, who it's for, key differentiators |
| [Frameworks](product/frameworks.md) | 14 compliance frameworks, 1,996 controls, crosswalks |

## Features

| Document | Description |
|----------|-------------|
| [Connectors](features/connectors.md) | 362 source connectors across 39 categories |
| [Assessment Engine](features/assessment-engine.md) | 4-tier assessment — assertions, AI, OPA, inheritance |

## API & CLI

| Document | Description |
|----------|-------------|
| [API Reference](api/reference.md) | 260 REST endpoints across 15 router files |
| [CLI Reference](api/cli-reference.md) | 809 leaf commands across 98 modules |

## Operations

| Document | Description |
|----------|-------------|
| [Deployment](operations/deployment.md) | Local dev, environment variables, production config |
| [Developer Setup](operations/developer-setup.md) | Local Python setup, testing, linting, QA gate, project structure |
| [Runbook](operations/runbook.md) | QA gate, pipeline ops, troubleshooting, monitoring |
| [SSO / IdP runbooks](operations/sso-idp-runbooks.md) | Azure AD, Okta, Google OIDC — redirect URIs, Redis, troubleshooting |
| [Enterprise SLA template](operations/enterprise-sla-template.md) | Non-binding SLA/support structure for procurement |

## Integrations (enterprise)

| Document | Description |
|----------|-------------|
| [Integration matrix](integrations/integration-matrix.md) | Jira, ServiceNow, Slack, Teams, PagerDuty — auth, direction, status |
| [Integrations roadmap](integrations/integrations-roadmap.md) | POC recommendations, SAML/SCIM notes, webhook pointers |
