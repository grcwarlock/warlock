# OPA/Rego Integration for Warlock v2

## Overview

Open Policy Agent (OPA) with Rego provides a declarative policy-as-data layer for Warlock's assessment pipeline. Rather than replacing the existing Python assertion engine, OPA sits alongside it as a complementary evaluation tier — giving auditors readable policies, hot-reloadable rules, and built-in policy testing.

## Where OPA Fits in the Pipeline

```
Ingest → Normalize → Map → Assess
                              ├── Tier 1a: OPA/Rego policies (declarative, auditor-friendly)
                              ├── Tier 1b: Python assertions (complex logic)
                              └── Tier 2: AI reasoning
```

- **Tier 1a (Rego):** Deterministic checks expressed as declarative policy files. Best for straightforward compliance rules that auditors need to review.
- **Tier 1b (Python):** Retained for assertions requiring complex data traversal, external lookups, or logic that doesn't translate cleanly to Rego.
- **Tier 2 (AI):** Unchanged — handles controls that lack deterministic assertions or where Tier 1 results are uncertain.

The assessment engine resolves evaluation order: if a Rego policy exists for a control binding, it runs first. If no Rego policy exists, it falls back to the Python assertion. If neither exists, Tier 2 AI reasoning is invoked.

## Why OPA for GRC

| Benefit | Detail |
|---------|--------|
| **Auditor readability** | Rego is closer to natural language than Python. Auditors can review and approve policy logic without reading application code. |
| **Policy versioning** | Policy files are versioned independently from application code. Git history shows exactly when and why a compliance rule changed. |
| **Built-in testing** | `opa test` provides unit testing with coverage reporting, purpose-built for policy validation. |
| **Hot reload** | Policies can be updated without redeploying the platform. OPA server mode watches for file changes. |
| **OSCAL alignment** | Each `.rego` file maps 1:1 to a control assertion, making it straightforward to reference in OSCAL exports. |
| **Ecosystem** | Conftest for config testing, Gatekeeper for Kubernetes enforcement, Regal for linting — all reusable within the Warlock platform. |

## Example: MFA Check in Rego

The existing `mfa_enabled` Python assertion (~60 lines with nested conditionals) translates to a declarative Rego policy:

```rego
package warlock.assertions.mfa_enabled

import rego.v1

default pass := false

# AWS IAM — console user without MFA
pass if {
    input.detail.mfa_active != null
    not _aws_missing_mfa
}

reasons contains msg if {
    _aws_missing_mfa
    msg := sprintf("User %s has console access without MFA", [input.detail.user])
}

_aws_missing_mfa if {
    input.detail.password_enabled
    not input.detail.mfa_active
}

# Okta — has enrolled factors
pass if {
    count(input.detail.factors) > 0
}

pass if {
    count(input.detail.enrolled_factors) > 0
}

# Okta — no factors
reasons contains msg if {
    input.detail.status != null
    count(object.get(input.detail, "mfa_factors", [])) == 0
    msg := sprintf("Okta user %s — no MFA factors enrolled", [input.detail.login])
}
```

With a corresponding test file:

```rego
package warlock.assertions.mfa_enabled_test

import rego.v1

test_aws_mfa_enabled if {
    result := data.warlock.assertions.mfa_enabled with input as {
        "detail": {"mfa_active": true, "password_enabled": true, "user": "alice"}
    }
    result.pass == true
}

test_aws_mfa_missing if {
    result := data.warlock.assertions.mfa_enabled with input as {
        "detail": {"mfa_active": false, "password_enabled": true, "user": "bob"}
    }
    result.pass == false
    count(result.reasons) > 0
}

test_okta_factors_enrolled if {
    result := data.warlock.assertions.mfa_enabled with input as {
        "detail": {"factors": [{"factorType": "push", "provider": "OKTA"}]}
    }
    result.pass == true
}
```

Run with:

```bash
opa test policies/ -v
```

## Integration Approach

### Option A: OPA as a subprocess (simple, development)

```python
def evaluate_rego(self, policy_path: str, input_data: dict) -> tuple[bool, list[str]]:
    """Evaluate a Rego policy against input data."""
    result = subprocess.run(
        ["opa", "eval", "-d", policy_path, "-i", "/dev/stdin",
         "data.warlock.assertions"],
        input=json.dumps(input_data),
        capture_output=True, text=True
    )
    parsed = json.loads(result.stdout)
    passed = parsed["result"][0]["expressions"][0]["value"].get("pass", False)
    reasons = parsed["result"][0]["expressions"][0]["value"].get("reasons", [])
    return passed, reasons
```

### Option B: OPA as a sidecar server (production)

Run OPA as a persistent server that watches for policy changes:

```bash
opa run --server --watch policies/
```

Query via HTTP from the assessment engine:

```python
async def evaluate_rego(self, assertion_name: str, input_data: dict) -> tuple[bool, list[str]]:
    """Evaluate a Rego policy via OPA server."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"http://localhost:8181/v1/data/warlock/assertions/{assertion_name}",
            json={"input": input_data}
        )
        result = resp.json().get("result", {})
        return result.get("pass", False), result.get("reasons", [])
```

Option B is preferred for production: policies stay loaded in memory, changes are picked up automatically, and the HTTP interface is language-agnostic.

### Engine Resolution Order

Modify `AssertionEngine.evaluate` to check for a Rego policy before falling back to Python:

1. Check if a `.rego` policy exists for the assertion name
2. If yes, evaluate via OPA and return the result
3. If no, fall back to the registered Python assertion function
4. If neither exists, return `not_assessed` for Tier 2 AI pickup

## Proposed File Structure

```
warlock-v2/
  policies/
    assertions/
      mfa_enabled.rego
      mfa_enabled_test.rego
      encryption_at_rest.rego
      encryption_at_rest_test.rego
      password_policy.rego
      password_policy_test.rego
      logging_enabled.rego
      logging_enabled_test.rego
      ...
    frameworks/
      nist_800_53/
        bindings.rego          # (framework, control_id) → assertion_name
      soc2/
        bindings.rego
      iso27001/
        bindings.rego
      iso27701/
        bindings.rego
      iso42001/
        bindings.rego
      ucf/
        bindings.rego
    lib/
      helpers.rego             # shared utility rules (date parsing, etc.)
```

The `bindings.rego` files declare which assertion applies to which control, replacing the Python `engine.bind_control()` calls with auditable data:

```rego
package warlock.frameworks.nist_800_53

import rego.v1

bindings := {
    "IA-2":   "mfa_enabled",
    "IA-2(1)": "mfa_enabled",
    "IA-5":   "password_policy",
    "SC-28":  "encryption_at_rest",
    "AU-2":   "logging_enabled",
}
```

## Tooling

| Tool | Purpose | Repo |
|------|---------|------|
| `opa eval` | One-off policy evaluation | ~/Coding/opa |
| `opa test` | Unit tests with coverage for policies | ~/Coding/opa |
| `opa run --server` | Production policy server | ~/Coding/opa |
| `conftest` | Test Terraform/K8s configs against policies | ~/Coding/conftest |
| `regal` | Lint Rego files for style and correctness | ~/Coding/regal |
| Rego style guide | Idiomatic Rego patterns | ~/Coding/rego-style-guide |

## Next Steps

1. Install OPA: `brew install opa`
2. Port 3-5 existing Python assertions to Rego as a proof of concept
3. Add Rego evaluation path to `AssertionEngine`
4. Set up `opa test` in the existing test suite
5. Lint policies with Regal in CI
6. Migrate framework bindings from Python to `bindings.rego` files
