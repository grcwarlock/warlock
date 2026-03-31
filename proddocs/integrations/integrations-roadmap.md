# Integrations roadmap (buyer-facing)

## Generally available (code present)

- OIDC SSO (Azure AD, Okta, Google, generic) — see [SSO runbooks](../operations/sso-idp-runbooks.md).
- Jira, ServiceNow, Slack, Teams, PagerDuty notification paths — see [integration matrix](integration-matrix.md).

## Recommended enterprise POC pairings

1. **Jira + ServiceNow**: Demonstrates ticketing from compliance events into ITSM workflows most buyers recognize.
2. **Teams or Slack + PagerDuty**: Demonstrates chat + paging for critical control failures.

Run end-to-end in **your** staging with real credentials; demo seed simulates connector data but not external write APIs.

## Planned / requested (not exhaustive)

| Item | Status |
|------|--------|
| **SAML 2.0 SP** | Not implemented — OIDC today. Evaluate when customers cannot use OIDC. |
| **SCIM provisioning** | Partial / SCIM module exists — align with product SCIM router and IdP docs. |
| **Bi-directional ServiceNow** | Push exists; deeper CMDB sync is roadmap per customer. |

## Webhooks

Inbound webhook contracts and signing should be documented alongside your **reverse proxy** and **TLS termination** setup. See API reference for routes under webhooks.

---

*Update this file when a capability moves from POC to GA.*
