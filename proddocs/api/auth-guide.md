# Authentication and Authorization Guide

Warlock supports two authentication methods: JWT bearer tokens for interactive sessions and API keys for programmatic access. All API endpoints under `/api/v1` require authentication except health checks and the trust portal.

## Quick Start

```bash
# 1. Login to get tokens
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@acme.com", "password": "WarlockAdmin2026!"}'

# Response:
# {"access_token": "eyJ...", "refresh_token": "abc...", "token_type": "bearer", "expires_in": 3600}

# 2. Use the access token
curl http://localhost:8000/api/v1/frameworks \
  -H "Authorization: Bearer eyJ..."
```

## JWT Bearer Tokens

### Obtaining a Token

```
POST /api/v1/auth/login
```

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123"
}
```

**Success response:**

```json
{
  "access_token": "eyJ...",
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Pass the access token in subsequent requests:

```
Authorization: Bearer eyJ...
```

### Token Lifetime

| Setting | Default | Environment Variable |
|---------|---------|---------------------|
| Access token expiry | 60 minutes | `WLK_JWT_EXPIRE_MINUTES` |
| Refresh token expiry | 30 days | Hardcoded |
| JWT algorithm | HS256 | Not configurable |
| JWT secret minimum length | 32 characters (enforced in non-dev) | `WLK_JWT_SECRET` |

In development, if `WLK_JWT_SECRET` is not set, an ephemeral secret is generated at startup. Tokens will not survive server restarts. In production (`WLK_ENV=production`), the server refuses to start without a JWT secret.

### Refreshing Tokens

Access tokens expire after 60 minutes by default. Use the refresh token to get a new pair without re-authenticating:

```
POST /api/v1/auth/refresh
```

```json
{
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4..."
}
```

**Response:** A new `access_token` and `refresh_token` pair. The old refresh token is immediately invalidated (rotation). Replaying a consumed refresh token returns 401.

### Token Revocation

To revoke all tokens for the current user (logout):

```
POST /api/v1/auth/logout
Authorization: Bearer eyJ...
```

This sets `token_valid_after` on the user record. All tokens issued before this timestamp are rejected on subsequent requests, including refresh tokens.

## API Key Authentication

API keys are for programmatic access (CI/CD, scripts, integrations). They do not expire by default but can be given an expiration.

### Creating an API Key

Requires `manage_keys` permission (admin or owner role).

```
POST /api/v1/auth/api-keys
Authorization: Bearer eyJ...
```

```json
{
  "name": "CI Pipeline Key",
  "scopes": ["read", "run_pipeline"],
  "expires_days": 90
}
```

**Response:**

```json
{
  "id": "uuid",
  "name": "CI Pipeline Key",
  "scopes": ["read", "run_pipeline"],
  "is_active": true,
  "created_at": "2026-03-23T00:00:00+00:00",
  "raw_key": "wlk_abc123..."
}
```

The `raw_key` is shown only once at creation. Store it securely. The server stores an HMAC-SHA256 hash of the key, not the key itself.

### Using an API Key

Pass the key in the `X-Api-Key` header:

```bash
curl http://localhost:8000/api/v1/frameworks \
  -H "X-Api-Key: wlk_abc123..."
```

### Scope Intersection

API key permissions are the intersection of the user's role permissions and the key's scopes. A read-only API key on an admin account only grants `read` access. If `scopes` is an empty list, the key has no permissions.

Valid scopes: `read`, `write`, `delete`, `manage_users`, `manage_keys`, `run_pipeline`, `export`.

### Managing API Keys

```
GET /api/v1/auth/api-keys          -- List your keys
DELETE /api/v1/auth/api-keys/{id}  -- Revoke a key
```

## RBAC Roles

Four roles control what actions a user can perform:

| Role | Permissions | Typical Use |
|------|-------------|-------------|
| `admin` | read, write, delete, manage_users, manage_keys, run_pipeline, export | Platform administrators |
| `auditor` | read, export | External auditors, read-only reviewers |
| `owner` | read, write, run_pipeline, export | Team leads scoped to specific frameworks |
| `viewer` | read | Dashboard viewers, stakeholders |

### Permission Descriptions

| Permission | Grants |
|-----------|--------|
| `read` | View findings, controls, results, reports, dashboards |
| `write` | Create/update issues, remediations, attestations, system profiles |
| `delete` | Remove records (admin only) |
| `manage_users` | Create, update, deactivate user accounts |
| `manage_keys` | Create, list, revoke API keys |
| `run_pipeline` | Trigger pipeline collection, start/stop scheduler |
| `export` | Generate OSCAL exports, evidence packages, reports |

## ABAC Scoping

Users can be restricted to specific data boundaries beyond their role. These filters are applied automatically to all query results.

| Field | Model Column | Effect |
|-------|-------------|--------|
| `allowed_frameworks` | `User.allowed_frameworks` | Limits visible frameworks (e.g., `["nist_800_53", "soc2"]`). Empty list = all frameworks. |
| `allowed_sources` | `User.allowed_sources` | Limits visible data sources/providers. Empty list = all sources. |
| `allowed_control_families` | `User.allowed_control_families` | Limits visible control families. Empty list = all families. |

Set these fields via `PUT /api/v1/users/{user_id}` (requires `manage_users`):

```json
{
  "allowed_frameworks": ["nist_800_53", "soc2"],
  "allowed_sources": ["aws", "crowdstrike"]
}
```

When a user with scoping restrictions queries `/api/v1/results`, only results matching their allowed frameworks are returned. No 403 error -- the results are silently filtered.

## MFA / TOTP

Warlock supports time-based one-time passwords (TOTP) compatible with Google Authenticator, Authy, and similar apps.

### Enrollment Flow

1. **Start enrollment** -- The admin or user calls the MFA enrollment endpoint. The server generates a TOTP secret and 10 backup codes.
2. **Scan QR code** -- The response includes a `provisioning_uri` (otpauth:// URI) for QR code generation. The raw `secret` is also returned for manual entry.
3. **Confirm enrollment** -- The user submits a valid 6-digit TOTP code to confirm. MFA is not active until confirmed.

### MFA Login Flow

When MFA is enabled, `POST /auth/login` returns a partial response:

```json
{
  "mfa_required": true,
  "mfa_token": "signed_challenge_token",
  "message": "MFA verification required. POST to /auth/mfa/verify with mfa_token and code."
}
```

Complete the login:

```
POST /api/v1/auth/mfa/verify
```

```json
{
  "mfa_token": "signed_challenge_token",
  "code": "123456"
}
```

The `mfa_token` is a signed, time-limited challenge (5 minutes). It replaces exposing raw user IDs in the MFA flow.

### Backup Codes

Ten single-use backup codes are generated during enrollment. Each code is an 8-character hex string, stored as a PBKDF2-SHA256 hash (600k iterations). When a backup code is used, it is consumed and cannot be reused.

## Account Lockout

After 5 consecutive failed login attempts, the account is locked for 30 minutes. During lockout, all login attempts return 401 with no indication that the account is locked (to prevent user enumeration).

| Setting | Value |
|---------|-------|
| Max failed attempts | 5 |
| Lockout duration | 30 minutes |
| Timing oracle prevention | Dummy hash verification on non-existent users |

## Password Requirements

| Requirement | Value |
|-------------|-------|
| Minimum length | 12 characters |
| Uppercase | At least 1 |
| Lowercase | At least 1 |
| Digit | At least 1 |
| Hash algorithm | bcrypt (12 rounds), PBKDF2-SHA256 fallback |
| Legacy hash migration | SHA-256 hashes auto-upgrade on next login |

## User Registration

Creating new users requires the `manage_users` permission (admin role):

```
POST /api/v1/auth/register
Authorization: Bearer eyJ...
```

```json
{
  "email": "analyst@acme.com",
  "name": "Jane Smith",
  "password": "SecurePassword123",
  "role": "auditor"
}
```

Returns the created user (without password). Duplicate emails return 409.

## Security Notes

- API keys are hashed with HMAC-SHA256 using the JWT secret as the HMAC key. Legacy SHA-256 key hashes are auto-migrated on use.
- CORS is configured via `WLK_CORS_ORIGINS`. Wildcard (`*`) origins are rejected at startup when credentials are enabled.
- All API responses include `Cache-Control: no-store` to prevent caching of sensitive data.
- Request audit logging captures every authenticated API call with caller identity, path, status, and duration.
