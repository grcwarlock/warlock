#!/usr/bin/env bash
# Warlock pre-commit quick QA gate
# Target: < 15 seconds total
# Runs: lint, fast tests, import smoke, secrets scan on staged files
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VENV=".venv/bin"
FAILED=0

section() {
    printf "\n=== %s ===\n" "$1"
}

fail_section() {
    printf "  FAILED: %s\n" "$1"
    FAILED=1
}

# --- 1. Ruff lint ---
section "Ruff lint"
if "$VENV/ruff" check warlock/ --quiet 2>/dev/null; then
    echo "  PASS"
else
    fail_section "ruff check found lint errors"
fi

# --- 2. Fast pytest (skip slow/integration) ---
section "Fast tests"
if "$VENV/pytest" tests/ -x -q --tb=line -m "not slow and not integration" 2>/dev/null; then
    echo "  PASS"
else
    fail_section "pytest failed"
fi

# --- 3. Import smoke test ---
section "Import smoke test"
if "$VENV/python" -c "import warlock; print('  PASS')" 2>/dev/null; then
    :
else
    fail_section "cannot import warlock"
fi

# --- 4. Secrets scan on staged files ---
section "Secrets scan (staged files)"
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null || true)
if [ -n "$STAGED_FILES" ]; then
    # Check for common secret patterns in staged content
    SECRETS_FOUND=$(git diff --cached -U0 2>/dev/null | grep -iE \
        '(sk-ant-api|sk-proj-|AKIA[0-9A-Z]{16}|password\s*=\s*["\x27][^\"\x27]{8,}["\x27]|BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY)' \
        2>/dev/null || true)
    if [ -n "$SECRETS_FOUND" ]; then
        echo "  POTENTIAL SECRETS DETECTED in staged changes:"
        echo "$SECRETS_FOUND" | head -5
        echo ""
        echo "  If these are real credentials, unstage and remove them."
        echo "  If they are test fixtures or variable names, proceed."
        fail_section "potential secrets in staged files"
    else
        echo "  PASS (no secrets detected)"
    fi
else
    echo "  PASS (no staged files to scan)"
fi

# --- Summary ---
echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "PRE-COMMIT QA: FAILED"
    echo "Fix the issues above before committing."
    exit 1
fi

echo "PRE-COMMIT QA: PASSED"
exit 0
