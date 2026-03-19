# Low Findings — Nice to Have

Generated: 2026-03-19 from 14-agent parallel review

---

## L-1: Deprecated session.query(Model).get() — breaks on SQLAlchemy 2.1+

- **Files:** `warlock/workflows/poam.py:68,126`, `warlock/export/binder.py:70,227`
- **Agents:** code-reviewer, feature-dev:code-reviewer
- **Issue:** `session.query(Model).get(pk)` deprecated in SQLAlchemy 2.0, removed in 2.1.
- **Fix:**
  - [ ] Replace all 4 call sites with `session.get(Model, pk)`

---

## L-2: Version string duplicated in 3 places

- **Files:** `warlock/api/app.py:88,377,421`
- **Agents:** code-reviewer
- **Issue:** `"2.0.0a1"` hardcoded in HealthResponse default, FastAPI constructor, and health endpoint.
- **Fix:**
  - [ ] Define `__version__` in `warlock/__init__.py` and reference everywhere

---

## L-3: Login timing oracle — user enumeration via response time

- **Files:** `warlock/api/auth.py:232`
- **Agents:** penetration-tester, compliance-auditor
- **Issue:** When user not found, function returns immediately. When user exists but wrong password, bcrypt runs (~0.3s). Timing difference reveals whether email is registered.
- **Fix:**
  - [ ] Perform dummy `verify_password` against a fixed hash when user not found to normalize timing

---

## L-4: Posture scoring weights undocumented

- **Files:** `warlock/assessors/posture.py:92-98`
- **Agents:** grc-engineer
- **Issue:** `critical=5.0, high=4.0, medium=3.0, low=2.0, info=1.0` are hardcoded with no documented rationale. Auditors may challenge the methodology.
- **Fix:**
  - [ ] Add docstring or ADR documenting the weight rationale
  - [ ] Consider making weights configurable per system profile or framework

---

## L-5: Trust portal exposes exact non_compliant counts publicly

- **Files:** `warlock/api/trust_portal.py:95-174`
- **Agents:** penetration-tester
- **Issue:** Unauthenticated `/trust/status` returns exact `non_compliant` counts and `posture_score`. Reveals compliance gap severity to anyone.
- **Fix:**
  - [ ] Round/bin scores (e.g., "Good/Fair/Needs Improvement") rather than exact values
  - [ ] Remove `non_compliant` and `partial` counts from public response
  - [ ] Consider requiring a simple access token even for the trust portal
