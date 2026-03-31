# Integration matrix (enterprise)

Direction: **Out** = Warlock calls the system. **In** = external system calls Warlock or feeds the pipeline via connectors.

| Integration | Direction | Auth | Read / write | Module / notes |
|-------------|-----------|------|--------------|----------------|
| **Jira** | Out | HTTP Basic / PAT (env) | **Write** issues on `control.assessed` (EventBus) | `warlock/integrations/jira_integration.py`, `jira_sync.py` |
| **ServiceNow** | Out | Basic + Table API (env) | **Write** incidents | `warlock/integrations/servicenow_integration.py`, `servicenow_push.py` |
| **Slack** | Out | Incoming webhook URL | **Write** messages | `warlock/integrations/slack.py` |
| **Microsoft Teams** | Out | Incoming webhook URL | **Write** Adaptive Cards | `warlock/integrations/teams.py` |
| **PagerDuty** | Out | Events API v2 routing key | **Write** incidents | `warlock/integrations/pagerduty.py` |
| **STIX/TAXII** | Varies | TAXII credentials | **In/Out** threat intel (see module) | `warlock/integrations/stix_taxii.py` |
| **Email (SMTP)** | Out | `WLK_SMTP_*` | **Write** notifications | `warlock/integrations/email_notifications.py` |
| **Webhooks (HTTP)** | In | Signing per config | **In** pipeline / events | `warlock/api/routers/webhooks.py` — verify HMAC/secret per deployment doc |

**SSO / OIDC**: User authentication — see [SSO IdP runbooks](../operations/sso-idp-runbooks.md).

**Connectors** (350+ sources): Ingestion from clouds and tools — see [Connectors](../features/connectors.md).

---

*Status values are descriptive of code intent; certify each path in your environment before procurement commitments.*
