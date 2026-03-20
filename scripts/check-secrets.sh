#!/usr/bin/env bash
# Standalone secrets scanner for pre-commit hook
# Scans staged files for hardcoded credentials and API keys
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Patterns that indicate real secrets (not variable names or placeholders)
SECRET_PATTERNS='(sk-ant-api[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[a-zA-Z0-9]{36}|BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY)'

# Check staged diff content (not filenames — actual added lines)
STAGED_DIFF=$(git diff --cached -U0 2>/dev/null || true)

if [ -z "$STAGED_DIFF" ]; then
    exit 0
fi

# Only check added lines (lines starting with +, excluding +++ file headers)
MATCHES=$(echo "$STAGED_DIFF" | grep '^+' | grep -v '^+++' | grep -iE "$SECRET_PATTERNS" 2>/dev/null || true)

if [ -n "$MATCHES" ]; then
    echo "SECRETS DETECTED in staged changes:"
    echo ""
    echo "$MATCHES" | head -10
    echo ""
    echo "If these are real credentials:"
    echo "  1. git reset HEAD <file>"
    echo "  2. Remove the secret"
    echo "  3. Rotate the credential immediately"
    echo ""
    echo "To bypass (test fixtures only): git commit --no-verify"
    exit 1
fi

exit 0
