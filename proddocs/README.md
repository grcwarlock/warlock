# Warlock Product Documentation

Production documentation for the Warlock GRC platform. Updated as part of the QA gate.

## Technical

| Document | Description |
|----------|-------------|
| [Architecture](technical/architecture.md) | System architecture — 4-stage pipeline, storage, security model |
| [Data Model](technical/data-model.md) | 36-table schema, relationships, JSON columns, pipeline data flow |
| [Data Lake](technical/data-lake.md) | GRC Data Lake — 3 zones, 10 domains, DuckDB, Iceberg, RAG |
| [Security](technical/security.md) | Auth (JWT/API keys/MFA), ABAC, OPA, audit trail, GDPR |

## Product

| Document | Description |
|----------|-------------|
| [Overview](product/overview.md) | What Warlock is, who it's for, key differentiators |
| [Frameworks](product/frameworks.md) | 14 compliance frameworks, 1,996 controls, crosswalks |

## Features

| Document | Description |
|----------|-------------|
| [Connectors](features/connectors.md) | 165 source connectors across 24 categories |
| [Assessment Engine](features/assessment-engine.md) | 4-tier assessment — assertions, AI, OPA, inheritance |

## API & CLI

| Document | Description |
|----------|-------------|
| [API Reference](api/reference.md) | 160 REST endpoints across 10 domain groups |
| [CLI Reference](api/cli-reference.md) | 40+ commands across 8 groups |

## Operations

| Document | Description |
|----------|-------------|
| [Deployment](operations/deployment.md) | Docker, local dev, environment variables, production config |
| [Runbook](operations/runbook.md) | QA gate, pipeline ops, troubleshooting, monitoring |
