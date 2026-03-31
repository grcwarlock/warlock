# SAML 2.0 Service Provider (roadmap)

## Current state

- Warlock supports **OIDC** for interactive login (`warlock/api/sso.py`).
- **SAML 2.0 SP** is **not** implemented in the application.

## Why it appears on enterprise RFPs

Many organizations standardized on **SAML** before OIDC adoption. Some IdPs still lead with SAML for **SSO to SaaS**.

## If we build it (spike checklist)

- Library: e.g. `python3-saml` or IdP-specific SDK — evaluate XML signature validation, metadata exchange, clock skew.
- **Same user link** as OIDC: match `NameID` / email to `User.sso_subject_id` / `email`.
- **Parallel to OIDC**: keep OIDC path for customers who prefer it.
- **Effort**: typically **multi-week** for robust SP (metadata, logout, encryption, multiple IdPs).

## Buyer criteria before committing

- Must-have vs nice-to-have (many IdPs offer **OIDC** alongside SAML).
- IdP list (Azure AD, Okta, Ping, etc.) and **test tenants**.

---

*This file is planning-only; no SAML code ships until explicitly scheduled.*
