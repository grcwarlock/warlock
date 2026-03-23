# API Error Reference

All Warlock API errors return JSON with a `detail` field describing the problem. This document catalogs every error category, its causes, and how to resolve it.

## Error Response Format

Every error response uses this structure:

```json
{
  "detail": "Human-readable error message"
}
```

For validation errors (422), FastAPI returns a more detailed format:

```json
{
  "detail": [
    {
      "loc": ["body", "email"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

## Status Code Reference

| Code | Category | When It Happens |
|------|----------|-----------------|
| 400 | Bad Request | Invalid parameters, malformed input, invalid state values |
| 401 | Unauthorized | Missing credentials, expired token, invalid API key, revoked token |
| 403 | Forbidden | Insufficient role permissions, ABAC scope violation |
| 404 | Not Found | Resource does not exist or is outside ABAC scope |
| 409 | Conflict | Duplicate resource, invalid state transition, pipeline already running |
| 413 | Payload Too Large | Request body exceeds 10 MB |
| 422 | Validation Error | Pydantic model validation failure |
| 429 | Rate Limited | Too many requests in the current window |
| 503 | Service Unavailable | AI provider not configured, external dependency down |

---

## 400 Bad Request

Returned when input is syntactically valid JSON but semantically wrong.

**Invalid status filter:**

```
GET /api/v1/remediations?status=invalid_status
```

```json
{
  "detail": "Invalid status: invalid_status. Must be one of: assigned, closed, in_progress, open, verification"
}
```

**Invalid API key scopes:**

```
POST /api/v1/auth/api-keys
{"name": "test", "scopes": ["fake_scope"]}
```

```json
{
  "detail": "Invalid scopes: ['fake_scope']. Valid scopes: ['delete', 'export', 'manage_keys', 'manage_users', 'read', 'run_pipeline', 'write']"
}
```

**Attestation/engagement workflow errors:** Operations that violate workflow rules (e.g., approving an attestation that has not been submitted) return 400 with the specific rule violation in `detail`.

---

## 401 Unauthorized

Returned when authentication fails. The API never reveals whether a user account exists -- all auth failures return the same generic message.

| Scenario | Detail Message |
|----------|---------------|
| No credentials provided | `"Not authenticated"` |
| Invalid email or password | `"Invalid credentials"` |
| Expired JWT token | `"Invalid or expired token"` |
| Token missing `sub` claim | `"Token missing subject"` |
| Revoked token (post-logout) | `"Token has been revoked"` |
| Invalid API key | `"Invalid API key"` |
| User deactivated | `"User not found or inactive"` |
| Invalid MFA challenge token | `"Invalid or expired MFA challenge token"` |
| Wrong MFA code | `"Invalid MFA code"` |
| Invalid refresh token | `"Invalid or expired refresh token"` |

**Account lockout:** After 5 failed login attempts, the account is locked for 30 minutes. Locked accounts return `"Invalid credentials"` -- not a lockout-specific message.

---

## 403 Forbidden

Returned when the user is authenticated but lacks the required permission or ABAC scope.

**Insufficient role permission:**

```json
{
  "detail": "Permission denied: manage_users"
}
```

This means the user's role (or API key scopes) does not include the required permission. See the [Auth Guide](auth-guide.md) for the role-permission matrix.

**ABAC framework scope violation:**

```json
{
  "detail": "Access denied for this framework"
}
```

The user's `allowed_frameworks` list does not include the requested framework. This applies to risk analysis, policy coverage, and other framework-specific endpoints.

---

## 404 Not Found

Returned when the requested resource does not exist. Common messages:

| Resource | Detail Message |
|----------|---------------|
| Finding | `"Finding not found"` |
| Issue | `"Issue not found"` |
| Remediation | `"Remediation not found"` |
| Alert | `"Alert not found"` |
| API Key | `"API key not found"` |
| Attestation | `"Attestation not found"` |
| Engagement | `"Engagement not found"` |
| Connector | `"Connector not found: {provider}"` |
| Questionnaire | `"Questionnaire not found"` |

Resources filtered out by ABAC scoping also appear as 404 -- the API does not distinguish between "does not exist" and "you cannot see it."

---

## 409 Conflict

Returned when an operation conflicts with the current state of a resource.

**Pipeline already running:**

```
POST /api/v1/pipeline/collect
```

```json
{
  "detail": "Pipeline already running (run abc12345, started 2026-03-23T10:00:00+00:00)"
}
```

Wait for the current pipeline run to complete before starting another.

**Duplicate email on registration:**

```
POST /api/v1/auth/register
```

```json
{
  "detail": "Email already registered"
}
```

**Invalid remediation state transition:**

```
PATCH /api/v1/remediations/{id}/verify
```

```json
{
  "detail": "Invalid state transition: 'open' -> 'closed'. Allowed transitions from 'open': assigned"
}
```

The remediation workflow follows a strict state machine:

```
open -> assigned -> in_progress -> verification -> closed
```

Backward transitions are allowed: `assigned -> open`, `in_progress -> assigned`, `verification -> in_progress` (rejection).

**Alert state conflicts:** Alerts also enforce valid state transitions and return 409 for invalid ones.

---

## 413 Payload Too Large

Returned when the request body exceeds 10 MB. Enforced by both Content-Length header checking and actual body byte counting (catches chunked transfer encoding).

```json
{
  "detail": "Request body too large (max 10MB)"
}
```

---

## 422 Validation Error

Returned by FastAPI's Pydantic validation when request body fields fail type checking or constraints.

```json
{
  "detail": [
    {
      "loc": ["body", "password"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

Common causes:
- Missing required fields in the request body
- Wrong data types (string where integer expected)
- Values outside allowed ranges (`limit` must be 1-1000, `offset` must be >= 0)
- Malformed email addresses or UUIDs

---

## 429 Rate Limited

Returned when the client exceeds the request rate limit for an endpoint.

```json
{
  "detail": "Rate limit exceeded",
  "scope": "worker"
}
```

**Response headers:**

| Header | Description |
|--------|-------------|
| `Retry-After` | Seconds to wait before retrying (60) |
| `X-RateLimit-Scope` | `"worker"` (in-memory, per-process) or `"global"` (Redis-backed) |
| `X-RateLimit-Warning` | `"per-worker"` -- present only when using in-memory rate limiting |

**Per-endpoint limits:**

| Endpoint | Requests/min | Burst |
|----------|-------------|-------|
| `POST /auth/login` | 10 | 5 |
| `POST /auth/register` | 5 | 2 |
| `POST /trust/request-access` | 10 | 3 |
| `POST /ai/reason` | 30 | 5 |
| `POST /ai/converse` | 30 | 5 |
| `POST /risk/analyze` | 10 | 2 |
| `POST /pipeline/collect` | 5 | 2 |
| All other endpoints | 60 | 10 |

The effective limit is `requests_per_minute + burst`. For login, that means 15 requests per 60-second window.

When `X-RateLimit-Scope` is `"worker"`, rate limits are tracked per Uvicorn worker process. In production, configure `WLK_CACHE_URL` to point to Redis for global rate limiting across all workers.

---

## 503 Service Unavailable

Returned when an external dependency is not configured or reachable.

**AI service not configured:**

```json
{
  "detail": "AI service is not configured or disabled."
}
```

This means `WLK_AI_PROVIDER` and `WLK_AI_API_KEY` are not set. AI endpoints (`/ai/reason`, `/ai/converse`, `/ai/conversations`) require a configured AI provider (Gemini, OpenAI, or Anthropic).

**AI provider connection failure:**

```json
{
  "detail": "AI provider not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY."
}
```

---

## Response Headers on All Requests

Every response includes security and diagnostic headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
| `Content-Security-Policy` | `default-src 'self'` | XSS prevention |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Cache-Control` | `no-store` | Prevent caching of API responses |
| `X-Correlation-ID` | UUID | Request correlation for debugging |
| `X-RateLimit-Scope` | `worker` or `global` | Rate limit enforcement mode |

## Troubleshooting Checklist

1. **Getting 401 on every request?** Check that your token has not expired (default: 60 min). Use `/auth/refresh` to get a new one.
2. **Getting 403 but you are logged in?** Your role lacks the required permission. Check the [Auth Guide](auth-guide.md) role table.
3. **Getting 429 but making few requests?** In per-worker mode, multiple workers have independent counters. Configure Redis via `WLK_CACHE_URL` for accurate global limits.
4. **Getting 409 on pipeline collect?** A pipeline run is already in progress. Check status at `GET /api/v1/pipeline/status`.
5. **Getting 503 on AI endpoints?** Set `WLK_AI_PROVIDER` and `WLK_AI_API_KEY` environment variables.
