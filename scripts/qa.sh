#!/usr/bin/env bash
# ==========================================================================
# Warlock QA Gate — Single-command, pass-or-fail quality assurance
#
# Usage:
#   ./scripts/qa.sh          # full QA gate
#   ./scripts/qa.sh --quick  # lint + test only (~30s)
#
# Exit codes:
#   0 = all checks passed
#   1 = one or more checks failed
# ==========================================================================
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

# ---------------------------------------------------------------------------
# Color and formatting
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

QUICK=false
[[ "${1:-}" == "--quick" ]] && QUICK=true

# ---------------------------------------------------------------------------
# State tracking
# ---------------------------------------------------------------------------
declare -a SECTION_NAMES=()
declare -a SECTION_RESULTS=()
declare -a SECTION_TIMES=()
FAILURES=0

section_start() {
    SECTION_NAMES+=("$1")
    printf "\n${BOLD}${CYAN}── %s ──${RESET}\n" "$1"
    SECTION_START_TIME=$(python3 -c "import time; print(time.time())")
}

section_pass() {
    local elapsed
    elapsed=$(python3 -c "import time; print(f'{time.time() - $SECTION_START_TIME:.1f}s')")
    SECTION_RESULTS+=("PASS")
    SECTION_TIMES+=("$elapsed")
    printf "  ${GREEN}PASS${RESET} ${DIM}(%s)${RESET}\n" "$elapsed"
}

section_fail() {
    local elapsed
    elapsed=$(python3 -c "import time; print(f'{time.time() - $SECTION_START_TIME:.1f}s')")
    SECTION_RESULTS+=("FAIL")
    SECTION_TIMES+=("$elapsed")
    FAILURES=$((FAILURES + 1))
    printf "  ${RED}FAIL${RESET} ${DIM}(%s)${RESET}\n" "$elapsed"
}

section_warn() {
    local elapsed
    elapsed=$(python3 -c "import time; print(f'{time.time() - $SECTION_START_TIME:.1f}s')")
    SECTION_RESULTS+=("WARN")
    SECTION_TIMES+=("$elapsed")
    printf "  ${YELLOW}WARN${RESET} ${DIM}(%s)${RESET}\n" "$elapsed"
}

section_skip() {
    SECTION_RESULTS+=("SKIP")
    SECTION_TIMES+=("--")
    printf "  ${DIM}SKIP${RESET}\n"
}

# Determine python/pytest paths
PYTHON="${DIR}/.venv/bin/python"
PYTEST="${DIR}/.venv/bin/pytest"
RUFF="${DIR}/.venv/bin/ruff"
ALEMBIC="${DIR}/.venv/bin/alembic"

if [[ ! -x "$PYTHON" ]]; then
    echo -e "${RED}ERROR: .venv not found. Run: python3 -m venv .venv && pip install -e '.[dev,ai]'${RESET}"
    exit 1
fi

TOTAL_START=$(python3 -c "import time; print(time.time())")

printf "\n${BOLD}========================================${RESET}\n"
printf "${BOLD}  Warlock QA Gate${RESET}"
if $QUICK; then
    printf " ${YELLOW}(quick mode)${RESET}"
fi
printf "\n${BOLD}========================================${RESET}\n"

# ==========================================================================
# SECTION 1: Code Quality
# ==========================================================================

# --- Ruff Lint ---
section_start "Ruff Lint"
if "$RUFF" check warlock/ 2>&1; then
    section_pass
else
    echo "  Lint errors found. Run: ruff check warlock/ --fix"
    section_fail
fi

# --- Ruff Format ---
section_start "Ruff Format Check"
if "$RUFF" format --check warlock/ > /dev/null 2>&1; then
    section_pass
else
    UNFORMATTED=$("$RUFF" format --check warlock/ 2>&1 | grep -c "Would reformat" || true)
    echo "  ${UNFORMATTED} files need formatting. Run: ruff format warlock/"
    section_fail
fi

# --- Import Verification ---
section_start "Package Import"
if "$PYTHON" -c "import warlock; print('  warlock package imports OK')" 2>&1; then
    section_pass
else
    section_fail
fi

# ==========================================================================
# SECTION 2: Testing
# ==========================================================================

# --- Pytest Full Suite ---
section_start "Pytest Suite"
PYTEST_OUTPUT=$("$PYTEST" tests/ --tb=short -q 2>&1) || true
echo "$PYTEST_OUTPUT" | tail -5
if echo "$PYTEST_OUTPUT" | grep -qE "passed"; then
    if echo "$PYTEST_OUTPUT" | grep -qE "failed|error"; then
        section_fail
    else
        section_pass
    fi
else
    section_fail
fi

# --- Test Count Baseline ---
section_start "Test Count Baseline (>= 190)"
COLLECT_OUTPUT=$("$PYTEST" --collect-only -q 2>&1) || true
TEST_COUNT=$(echo "$COLLECT_OUTPUT" | grep -oE "^[0-9]+ tests?" | head -1 | grep -oE "^[0-9]+")
TEST_COUNT=${TEST_COUNT:-0}
echo "  Collected: ${TEST_COUNT} tests"
if [[ "$TEST_COUNT" -ge 190 ]]; then
    section_pass
else
    echo "  Baseline is 190. Test count dropped!"
    section_fail
fi

# If --quick, skip everything below
if $QUICK; then
    printf "\n${BOLD}========================================${RESET}\n"
    printf "${BOLD}  Quick QA Complete${RESET}\n"
    printf "${BOLD}========================================${RESET}\n\n"

    # Summary table
    printf "${BOLD}%-35s %-6s %s${RESET}\n" "CHECK" "RESULT" "TIME"
    printf "%-35s %-6s %s\n" "---" "---" "---"
    for i in "${!SECTION_NAMES[@]}"; do
        RESULT="${SECTION_RESULTS[$i]}"
        case "$RESULT" in
            PASS) COLOR="$GREEN" ;;
            FAIL) COLOR="$RED" ;;
            WARN) COLOR="$YELLOW" ;;
            *)    COLOR="$DIM" ;;
        esac
        printf "%-35s ${COLOR}%-6s${RESET} %s\n" "${SECTION_NAMES[$i]}" "$RESULT" "${SECTION_TIMES[$i]}"
    done

    TOTAL_ELAPSED=$(python3 -c "import time; print(f'{time.time() - $TOTAL_START:.1f}s')")
    printf "\n${BOLD}Total: %s${RESET}\n" "$TOTAL_ELAPSED"

    if [[ "$FAILURES" -gt 0 ]]; then
        printf "\n${RED}${BOLD}FAILED: %d check(s) failed${RESET}\n\n" "$FAILURES"
        exit 1
    else
        printf "\n${GREEN}${BOLD}ALL CHECKS PASSED${RESET}\n\n"
        exit 0
    fi
fi

# ==========================================================================
# SECTION 3: Integration
# ==========================================================================

# --- Demo Seed on Clean DB ---
section_start "Demo Seed (clean DB)"
rm -f "${DIR}/warlock.db"
# Clean up pipeline lock file from any prior run
LOCK_PATH="${TMPDIR:-/tmp}/warlock_pipeline.lock"
rm -f "$LOCK_PATH"
export WLK_AI_ENABLED=false
SEED_OK=true
"$ALEMBIC" upgrade head > /dev/null 2>&1 || SEED_OK=false
if $SEED_OK; then
    SEED_OUTPUT=$("$PYTHON" scripts/demo_seed.py 2>&1) || SEED_OK=false
fi
if $SEED_OK; then
    # Verify key counts from seed output
    CONN_COUNT=$(echo "$SEED_OUTPUT" | grep -oE "Connectors succeeded:\s+[0-9]+" | grep -oE "[0-9]+" || echo "0")
    CONN_FAIL=$(echo "$SEED_OUTPUT" | grep -oE "Connectors failed:\s+[0-9]+" | grep -oE "[0-9]+" || echo "?")
    echo "  Connectors succeeded: ${CONN_COUNT}, failed: ${CONN_FAIL}"
    if [[ "$CONN_COUNT" -ge 43 && "$CONN_FAIL" == "0" ]]; then
        section_pass
    else
        echo "  Expected >= 43 succeeded, 0 failed"
        section_fail
    fi
else
    echo "  Seed or migration failed"
    section_fail
fi

# --- CLI Smoke Test (--help on every command) ---
section_start "CLI Smoke Test (--help)"
CLI_CMDS=$("$PYTHON" -c "
from warlock.cli import cli
for name in sorted(cli.commands.keys()):
    print(name)
" 2>/dev/null) || CLI_CMDS=""
CLI_FAIL=0
CLI_TOTAL=0
for cmd in $CLI_CMDS; do
    CLI_TOTAL=$((CLI_TOTAL + 1))
    if ! "$PYTHON" -m warlock --help > /dev/null 2>&1; then
        # Fallback: use click runner approach
        true
    fi
    # Use the Click CliRunner via Python for reliability
    RESULT=$("$PYTHON" -c "
from warlock.cli import cli
from click.testing import CliRunner
r = CliRunner().invoke(cli, ['${cmd}', '--help'])
exit(0 if r.exit_code == 0 else 1)
" 2>&1) || {
        echo "  FAIL: warlock ${cmd} --help"
        CLI_FAIL=$((CLI_FAIL + 1))
    }
done
echo "  ${CLI_TOTAL} commands tested, ${CLI_FAIL} failures"
if [[ "$CLI_FAIL" -eq 0 ]]; then
    section_pass
else
    section_fail
fi

# --- Integrations Import ---
section_start "Integrations Import Verification"
if "$PYTHON" -c "
from warlock.integrations.slack import SlackNotifier
from warlock.integrations.pagerduty import PagerDutyNotifier
from warlock.integrations.jira_integration import JiraNotifier
from warlock.integrations.servicenow_integration import ServiceNowNotifier
print('  All 4 outbound integrations import OK')
" 2>&1; then
    section_pass
else
    echo "  Integrations import failed"
    section_fail
fi

# ==========================================================================
# SECTION 4: Compliance Infrastructure
# ==========================================================================

# --- OPA ---
section_start "OPA Policy Check"
if command -v opa &>/dev/null; then
    OPA_OK=true
    opa check policies/ 2>&1 || OPA_OK=false
    if $OPA_OK; then
        OPA_TEST_OUT=$(opa test policies/ 2>&1) || OPA_OK=false
    fi
    if $OPA_OK; then
        echo "  $(echo "$OPA_TEST_OUT" | tail -1)"
        section_pass
    else
        section_fail
    fi
else
    echo "  OPA not installed -- skipping (install with: brew install opa)"
    section_skip
fi

# --- Terraform Validate ---
section_start "Terraform Validate"
if command -v terraform &>/dev/null; then
    TF_FAIL=0
    TF_TOTAL=0
    for tfdir in "${DIR}"/terraform/modules/*/*; do
        [[ -d "$tfdir" ]] || continue
        TF_TOTAL=$((TF_TOTAL + 1))
        pushd "$tfdir" > /dev/null
        terraform init -backend=false -input=false > /dev/null 2>&1
        if terraform validate > /dev/null 2>&1; then
            true
        else
            echo "  FAIL: $tfdir"
            TF_FAIL=$((TF_FAIL + 1))
        fi
        popd > /dev/null
    done
    echo "  ${TF_TOTAL} modules validated, ${TF_FAIL} failures"
    if [[ "$TF_FAIL" -eq 0 ]]; then
        section_pass
    else
        section_fail
    fi
else
    echo "  Terraform not installed -- skipping"
    section_skip
fi

# --- Terraform Format ---
section_start "Terraform Format Check"
if command -v terraform &>/dev/null; then
    if terraform fmt -check -recursive terraform/ > /dev/null 2>&1; then
        section_pass
    else
        echo "  Formatting issues found. Run: terraform fmt -recursive terraform/"
        section_fail
    fi
else
    echo "  Terraform not installed -- skipping"
    section_skip
fi

# --- OSCAL JSON ---
section_start "OSCAL JSON Validation"
OSCAL_RESULT=$("$PYTHON" -c "
import json, pathlib, sys
errors = []
count = 0
for f in pathlib.Path('frameworks-oscal').rglob('*.json'):
    count += 1
    try:
        json.loads(f.read_text())
    except Exception as e:
        errors.append(f'{f}: {e}')
if errors:
    for e in errors:
        print(f'  BROKEN: {e}', file=sys.stderr)
    sys.exit(1)
print(f'  {count} OSCAL JSON files validated')
" 2>&1) || true
echo "$OSCAL_RESULT"
if echo "$OSCAL_RESULT" | grep -q "BROKEN"; then
    section_fail
else
    section_pass
fi

# --- Framework YAML ---
section_start "Framework YAML Validation"
FW_RESULT=$("$PYTHON" -c "
import yaml, pathlib, sys
errors = []
count = 0
for f in pathlib.Path('warlock/frameworks').glob('*.yaml'):
    if f.stem.startswith('crosswalk'):
        continue
    count += 1
    try:
        data = yaml.safe_load(f.read_text())
        if not isinstance(data, dict):
            errors.append(f'{f.name}: root is not a dict')
    except Exception as e:
        errors.append(f'{f.name}: {e}')
if errors:
    for e in errors:
        print(f'  BROKEN: {e}', file=sys.stderr)
    sys.exit(1)
print(f'  {count} framework YAMLs validated')
" 2>&1) || true
echo "$FW_RESULT"
if echo "$FW_RESULT" | grep -q "BROKEN"; then
    section_fail
else
    section_pass
fi

# ==========================================================================
# SECTION 5: Security
# ==========================================================================

# --- Secrets Scan ---
section_start "Secrets Scan"
# Search for real API keys, AWS keys, hardcoded passwords in Python files
# Exclude test files, .pyc, migrations, and this script
SECRETS_FOUND=$( (grep -rnE "(sk-ant-api[0-9]|sk-proj-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|password\s*=\s*['\"][^'\"]{12,}['\"])" \
    --include="*.py" --exclude-dir=".venv" --exclude-dir="__pycache__" \
    --exclude-dir="tests" --exclude="qa.sh" \
    warlock/ scripts/ 2>/dev/null || true) | grep -v "placeholder" | grep -v "example" | grep -v "your-" | grep -v "WarlockAdmin" | grep -v "# " || true)
if [[ -z "$SECRETS_FOUND" ]]; then
    echo "  No hardcoded secrets detected"
    section_pass
else
    echo "  Potential secrets found:"
    echo "$SECRETS_FOUND" | head -5
    section_fail
fi

# --- No .env Committed ---
section_start "No .env Files Committed"
if git ls-files --error-unmatch .env > /dev/null 2>&1; then
    echo "  .env is tracked by git!"
    section_fail
else
    echo "  No .env in git"
    section_pass
fi

# --- Dependency Audit ---
section_start "Dependency Vulnerability Audit"
if "$DIR/.venv/bin/pip-audit" --version > /dev/null 2>&1; then
    AUDIT_OUTPUT=$("$DIR/.venv/bin/pip-audit" 2>&1) || true
    VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -cE "^[a-zA-Z].*\s+(HIGH|CRITICAL)" || true)
    if [[ "$VULN_COUNT" -gt 0 ]]; then
        echo "  $VULN_COUNT HIGH/CRITICAL vulnerabilities found"
        echo "$AUDIT_OUTPUT" | grep -E "(HIGH|CRITICAL)" | head -5
        section_warn
    else
        echo "  No HIGH/CRITICAL vulnerabilities"
        section_pass
    fi
else
    echo "  pip-audit not installed. Run: pip install pip-audit"
    section_skip
fi

# --- Migration Reversibility ---
section_start "Migration Reversibility"
rm -f "${DIR}/warlock.db"
MIG_OK=true
"$ALEMBIC" upgrade head > /dev/null 2>&1 || MIG_OK=false
if $MIG_OK; then
    "$ALEMBIC" downgrade -1 > /dev/null 2>&1 || MIG_OK=false
fi
if $MIG_OK; then
    echo "  upgrade + downgrade -1 succeeded"
    section_pass
else
    echo "  Migration reversibility failed"
    section_fail
fi

# ==========================================================================
# SECTION 6: Documentation Consistency
# ==========================================================================

section_start "Documentation Count Verification"
if "$PYTHON" scripts/verify_docs.py 2>&1; then
    section_pass
else
    section_fail
fi

# ==========================================================================
# SECTION 7: AI Layer
# ==========================================================================

# --- AI Task Prompts ---
section_start "AI Task Prompt Coverage"
AI_RESULT=$("$PYTHON" -c "
from warlock.ai.types import AITask
from warlock.ai.tasks import TASK_PROMPTS
missing = [t.value for t in AITask if t not in TASK_PROMPTS]
if missing:
    print(f'  Missing prompts for: {missing}')
    exit(1)
print(f'  All {len(list(AITask))} AI task types have registered prompts')
" 2>&1) || true
echo "$AI_RESULT"
if echo "$AI_RESULT" | grep -qE "Missing|Error|Traceback|ImportError"; then
    section_fail
else
    section_pass
fi

# --- CLI AI Flags ---
section_start "CLI AI/Ask Flags"
AI_FLAG_RESULT=$("$PYTHON" -c "
from warlock.cli import cli
from click.testing import CliRunner
runner = CliRunner()
errors = []

# ai group must exist
r = runner.invoke(cli, ['--help'])
if 'ai ' not in r.output and 'ai' not in r.output:
    errors.append('ai group missing from top-level help')

# --ai flag on key commands
for cmd in ['coverage', 'control', 'remediate', 'simulate-audit', 'policy-coverage']:
    parts = cmd.split('-')
    r = runner.invoke(cli, [cmd, '--help'])
    if '--ai' not in r.output:
        errors.append(f'{cmd} missing --ai flag')

# --ask flag on interactive commands
for cmd in ['remediate', 'control', 'findings', 'issues']:
    r = runner.invoke(cli, [cmd, '--help'])
    if '--ask' not in r.output:
        errors.append(f'{cmd} missing --ask flag')

if errors:
    for e in errors:
        print(f'  FAIL: {e}')
    exit(1)
print('  All expected --ai and --ask flags present')
" 2>&1) || true
echo "$AI_FLAG_RESULT"
if echo "$AI_FLAG_RESULT" | grep -q "FAIL:"; then
    section_fail
else
    section_pass
fi

# --- AI Service Import ---
section_start "AI Service Import"
if "$PYTHON" -c "from warlock.ai.service import get_ai_service; print('  AI service imports cleanly')" 2>&1; then
    section_pass
else
    section_fail
fi

# --- Network Connectors ---
section_start "Network Connector Import"
NET_RESULT=$("$PYTHON" -c "
from warlock.connectors.palo_alto import PaloAltoConnector
from warlock.connectors.fortinet import FortinetConnector
from warlock.connectors.zscaler import ZscalerConnector
from warlock.normalizers.palo_alto import PaloAltoNormalizer
from warlock.normalizers.fortinet import FortinetNormalizer
from warlock.normalizers.zscaler import ZscalerNormalizer
from warlock.connectors.base import SourceType
assert hasattr(SourceType, 'NETWORK'), 'NETWORK source type missing'
print('  All 3 network connectors + normalizers + NETWORK source type OK')
" 2>&1) || true
echo "$NET_RESULT"
if echo "$NET_RESULT" | grep -qE "Error|Traceback|assert"; then
    section_fail
else
    section_pass
fi

# --- Vector / RAG ---
section_start "Vector/RAG Import"
RAG_RESULT=$("$PYTHON" -c "
from warlock.ai.embeddings import EmbeddingProvider, cosine_similarity
from warlock.ai.rag import VectorStore, SemanticMapper
from warlock.db.models import Embedding
# Verify cosine_similarity works
sim = cosine_similarity([1.0, 0.0, 0.0], [1.0, 0.0, 0.0])
assert abs(sim - 1.0) < 0.001, f'cosine_similarity(identical) should be 1.0, got {sim}'
sim2 = cosine_similarity([1.0, 0.0], [0.0, 1.0])
assert abs(sim2) < 0.001, f'cosine_similarity(orthogonal) should be 0.0, got {sim2}'
print('  Embeddings, VectorStore, SemanticMapper, cosine_similarity OK')
" 2>&1) || true
echo "$RAG_RESULT"
if echo "$RAG_RESULT" | grep -qE "Error|Traceback|assert"; then
    section_fail
else
    section_pass
fi

# --- Outbound Integration Registration ---
section_start "EventBus Subscriber Registration"
BUS_RESULT=$("$PYTHON" -c "
import os
# Set env vars to trigger registration
os.environ['WLK_SLACK_WEBHOOK_URL'] = 'https://hooks.slack.com/test'
os.environ['WLK_PAGERDUTY_ROUTING_KEY'] = 'test-key'
os.environ['WLK_JIRA_BASE_URL'] = 'https://test.atlassian.net'
os.environ['WLK_SERVICENOW_INSTANCE'] = 'test'
from warlock.pipeline.bus import EventBus, _register_default_subscribers
bus = EventBus()
_register_default_subscribers(bus)
# Count registered handlers
handler_count = sum(len(v) for v in bus._handlers.values())
print(f'  {handler_count} event handlers registered across all event types')
if handler_count < 4:
    print('  Expected at least 4 handlers (Slack, PD, Jira, ServiceNow)')
    exit(1)
print('  All 4 outbound integrations register on EventBus OK')
" 2>&1) || true
echo "$BUS_RESULT"
if echo "$BUS_RESULT" | grep -qE "Error|Traceback|Expected"; then
    section_fail
else
    section_pass
fi

# --- CI Workflow Reality Check ---
section_start "CI Workflow Reality Check"
CI_OK=true
CI_FILE="${DIR}/.github/workflows/ci.yml"
if [ -f "$CI_FILE" ]; then
    # Extract CLI group names tested in CI and verify they exist
    CI_GROUPS=$(grep -oE '"[a-z_-]+"' "$CI_FILE" | tr -d '"' | sort -u)
    for grp in $CI_GROUPS; do
        # Only check if it looks like a warlock CLI command reference in the smoke test section
        if grep -q "warlock.*$grp.*--help" "$CI_FILE" 2>/dev/null; then
            if ! "$PYTHON" -c "from warlock.cli import cli; assert '$grp' in [c for c in cli.list_commands(None)]" 2>/dev/null; then
                # Check if it's a group (subcommand of a group)
                if ! "$PYTHON" -c "
from warlock.cli import cli
import click
for name, cmd in cli.commands.items():
    if isinstance(cmd, click.Group) and '$grp' in [c for c in cmd.list_commands(None)]:
        exit(0)
exit(1)
" 2>/dev/null; then
                    echo "  CI tests 'warlock $grp' but command does not exist"
                    CI_OK=false
                fi
            fi
        fi
    done
    if $CI_OK; then
        echo "  All CI-referenced CLI commands exist"
        section_pass
    else
        section_fail
    fi
else
    echo "  CI workflow not found — skipping"
    section_skip
fi

# ==========================================================================
# SUMMARY
# ==========================================================================

printf "\n${BOLD}========================================${RESET}\n"
printf "${BOLD}  QA Summary${RESET}\n"
printf "${BOLD}========================================${RESET}\n\n"

printf "${BOLD}%-40s %-6s %s${RESET}\n" "CHECK" "RESULT" "TIME"
printf "%-40s %-6s %s\n" "----------------------------------------" "------" "----"
for i in "${!SECTION_NAMES[@]}"; do
    RESULT="${SECTION_RESULTS[$i]}"
    case "$RESULT" in
        PASS) COLOR="$GREEN" ;;
        FAIL) COLOR="$RED" ;;
        WARN) COLOR="$YELLOW" ;;
        *)    COLOR="$DIM" ;;
    esac
    printf "%-40s ${COLOR}%-6s${RESET} %s\n" "${SECTION_NAMES[$i]}" "$RESULT" "${SECTION_TIMES[$i]}"
done

TOTAL_ELAPSED=$(python3 -c "import time; print(f'{time.time() - $TOTAL_START:.1f}s')")
printf "\n${BOLD}Total: %s${RESET}\n" "$TOTAL_ELAPSED"

if [[ "$FAILURES" -gt 0 ]]; then
    printf "\n${RED}${BOLD}FAILED: %d check(s) failed. Fix before committing.${RESET}\n\n" "$FAILURES"
    exit 1
else
    printf "\n${GREEN}${BOLD}ALL CHECKS PASSED${RESET}\n\n"
    exit 0
fi
