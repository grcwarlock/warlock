# SSO / OIDC IdP runbooks (enterprise)

Warlock uses **OIDC** (`/api/v1/auth/sso/login` → IdP → `/api/v1/auth/sso/callback`). Production requires **`WLK_CACHE_URL`** (Redis) so OAuth **state** is shared across API workers (GAP-077).

## Common setup

1. **Redirect URI** registered at the IdP (exact match):
   - `https://<your-api-host>/api/v1/auth/sso/callback`
2. **Scopes**: `openid email profile` (required for email and subject).
3. **Secrets**: `WLK_SSO_CLIENT_ID`, `WLK_SSO_CLIENT_SECRET`, `WLK_SSO_ISSUER_URL`, `WLK_SSO_PROVIDER`.
4. **Redis**: `WLK_CACHE_URL=redis://...` (mandatory when `WLK_ENV=production` and `WLK_SSO_ENABLED=true`).

## Azure AD (`WLK_SSO_PROVIDER=azure_ad`)

- **Issuer URL**: `https://login.microsoftonline.com/<tenant-id>/v2.0` (directory tenant ID or `common` for multi-tenant apps).
- **App registration**: Web redirect URI as above; enable **ID tokens**; add client secret.
- **Optional groups → Warlock role**: emit **groups** or **roles** in the token (may require **Token configuration** + optional **Group claims** for `groups`). Set `WLK_SSO_GROUPS_CLAIM=groups` and `WLK_SSO_ROLE_MAPPING` JSON (see deployment doc).

## Okta (`WLK_SSO_PROVIDER=okta`)

- **Issuer URL**: `https://<your-oauth-domain>.okta.com/oauth2/default` (or custom authorization server).
- **Application**: OIDC Web; sign-in redirect URI as above; assign users/groups.
- **Groups claim**: Configure authorization server claim or use `groups` if exposed; map via `WLK_SSO_ROLE_MAPPING`.

## Google (`WLK_SSO_PROVIDER=google`)

- **Issuer URL**: `https://accounts.google.com`
- **Google Cloud Console**: OAuth 2.0 Client ID (Web application); authorized redirect URIs as above.
- **Workspace**: Restrict client to internal users via Workspace admin if required.

## Troubleshooting

| Symptom | Cause |
|--------|--------|
| `Invalid or expired state` after login | Missing Redis in multi-worker deployment, or load balancer not sticky and no Redis — set `WLK_CACHE_URL`. |
| `ID token issuer mismatch` | Issuer URL in Warlock must match token `iss` (Azure: use same tenant/v2.0 URL). |
| `missing email claim` | Add `email` scope; Azure may use `preferred_username` (supported in code). |

## Role mapping

- `WLK_SSO_GROUPS_CLAIM`: claim name containing group/role strings (list or string).
- `WLK_SSO_ROLE_MAPPING`: JSON object, e.g. `{"GRC-Admins":"admin","GRC-Viewers":"viewer"}`.
- First matching group wins; else `WLK_SSO_DEFAULT_ROLE`.

## SAML

SAML 2.0 Service Provider is **not** implemented; OIDC-only today. See `integrations-roadmap.md` for roadmap.
