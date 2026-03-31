# Enterprise SLA / support template (non-binding)

**This page is a template.** Commercial SLAs, uptime targets, and support hours belong in **contracts** and are owned by **legal** and **sales**. Engineering uses this to stay aligned with what the platform can support.

## Service tiers (example structure)

| Tier | Audience | Support channel | Response target (example) |
|------|-----------|-----------------|----------------------------|
| **Community / self-hosted** | Internal teams | Docs, issues | Best effort |
| **Business** | Production self-hosted | Email | Business hours — e.g. 24h first response |
| **Enterprise** | Regulated / mission-critical | Named CSM + security alias | Contractual — e.g. 4h for P1 |

*Replace placeholders with numbers your organization commits to.*

## Availability

- **Application SLO**: Example: **99.5%** monthly API availability for **managed** endpoints, excluding:
  - Customer **cloud provider** outages
  - **Identity provider** (Azure AD, Okta, etc.) outages
  - **Third-party connector** APIs (AWS, scanners, etc.)
  - Planned maintenance announced **N** days in advance
- **Measurement**: Synthetic checks or load balancer health against `/health` / `/readyz`.

## Incidents and security

- **Incident process**: Document `security@` / `support@` aliases and escalation to on-call (PagerDuty/Slack integrations exist in codebase for **notifications** — process is operational).
- **Security disclosures**: Coordinated disclosure policy URL (add when published).

## Contract appendix

- Attach **SLA table**, **credit policy** (if any), **exclusions**, and **support hours** per region.

---

*Do not commit specific percentage SLAs in this repo without legal review.*
