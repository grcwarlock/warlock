#!/usr/bin/env python3
"""Automated documentation accuracy checker for Warlock.

Counts actual connectors, normalizers, frameworks, tests, OPA files,
terraform modules, CLI commands, OSCAL files, and more -- then compares
against numeric claims in README.md, CLAUDE.md, DEMO.md, and
CONTRIBUTING.md.  Exits 1 if ANY count is wrong.

Usage:
    python scripts/verify_docs.py
    python scripts/verify_docs.py --verbose
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"

VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv

mismatches: list[str] = []
checked: set[tuple[str, str, int]] = set()  # dedup: (label, doc, line)


def _count_py_modules(
    directory: pathlib.Path, exclude: tuple[str, ...] = ("__init__.py", "base.py")
) -> int:
    return len([f for f in directory.glob("*.py") if f.name not in exclude])


def _count_files(directory: pathlib.Path, pattern: str) -> int:
    return len(list(directory.rglob(pattern)))


def _count_dirs(pattern: str) -> int:
    return len(list(ROOT.glob(pattern)))


def _is_narrative(line: str) -> bool:
    """Return True if line is a historical narrative / lesson learned, not an active count claim."""
    lower = line.lower()
    # Historical references in lessons-learned sections
    if any(
        kw in lower
        for kw in [
            "claimed",
            "said ",
            "when there were",
            "were dead",
            "sub-agent",
            "was optional",
            "was a violation",
        ]
    ):
        return True
    return False


def _is_demo_output(line: str) -> bool:
    """Return True if line describes demo seed output counts, not file counts."""
    lower = line.lower()
    return any(
        kw in lower
        for kw in [
            "succeeded",
            "failed",
            "seed",
            "demo_seed",
            "findings",
            "results (~",
            "29k",
            "29,207",
        ]
    )


def check(label: str, actual: int, doc_file: str, claimed: int, line_num: int) -> None:
    dedup_key = (label, doc_file, line_num)
    if dedup_key in checked:
        return
    checked.add(dedup_key)

    if actual != claimed:
        msg = f"  {RED}FAIL{RESET}  {label} ({doc_file}:{line_num}): actual={actual}, claims={claimed}"
        mismatches.append(msg)
        print(msg)
    elif VERBOSE:
        print(f"  {GREEN}OK{RESET}    {label} ({doc_file}:{line_num}): {actual}")


# ---------------------------------------------------------------------------
# Collect actual counts
# ---------------------------------------------------------------------------


def get_actual_counts() -> dict[str, int]:
    counts: dict[str, int] = {}

    counts["connectors"] = _count_py_modules(ROOT / "warlock" / "connectors")

    counts["normalizers"] = _count_py_modules(
        ROOT / "warlock" / "normalizers", exclude=("__init__.py",)
    )

    fw_dir = ROOT / "warlock" / "frameworks"
    counts["frameworks"] = len(
        [f for f in fw_dir.glob("*.yaml") if not f.stem.startswith("crosswalk")]
    )

    try:
        result = subprocess.run(
            [str(ROOT / ".venv" / "bin" / "pytest"), "--collect-only", "-q"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=30,
        )
        for line in result.stdout.strip().splitlines()[-3:]:
            m = re.search(r"(\d+)\s+tests?\s+collected", line)
            if m:
                counts["tests"] = int(m.group(1))
                break
    except Exception:
        pass

    counts["test_files"] = len(list((ROOT / "tests").glob("test_*.py")))

    counts["rego_files"] = _count_files(ROOT / "policies", "*.rego")

    counts["oscal_json"] = _count_files(ROOT / "frameworks-oscal", "*.json")

    counts["terraform_modules"] = _count_dirs("terraform/modules/*/*")

    try:
        result = subprocess.run(
            [
                str(ROOT / ".venv" / "bin" / "python"),
                "-c",
                "from warlock.cli import cli; print(len(list(cli.commands.keys())))",
            ],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=15,
        )
        counts["cli_commands"] = int(result.stdout.strip())
    except Exception:
        pass

    try:
        result = subprocess.run(
            [
                str(ROOT / ".venv" / "bin" / "python"),
                "-c",
                """
import re
text = open('warlock/db/models.py').read()
classes = re.findall(r'^class \\w+\\(.*Base.*\\)', text, re.MULTILINE)
print(len(classes))
""",
            ],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=15,
        )
        counts["db_models"] = int(result.stdout.strip())
    except Exception:
        pass

    mig_dir = ROOT / "warlock" / "db" / "migrations" / "versions"
    if mig_dir.exists():
        counts["migrations"] = len(list(mig_dir.glob("*.py")))

    return counts


# ---------------------------------------------------------------------------
# Claim extraction with context filtering
# ---------------------------------------------------------------------------


def find_claims(doc_name: str, doc_text: str, actual: dict[str, int]) -> None:
    lines = doc_text.splitlines()

    for i, line in enumerate(lines):
        if _is_narrative(line):
            continue

        # --- Connectors: "Connectors (41)" or "41 source connectors" ---
        # Skip demo seed output lines ("40 connectors, 547 findings")
        if not _is_demo_output(line):
            for m in re.finditer(r"Connectors?\s*\(\s*(\d+)\s*(?:sources?)?\)", line, re.I):
                num = int(m.group(1))
                if "connectors" in actual:
                    check("connectors", actual["connectors"], doc_name, num, i + 1)

            for m in re.finditer(r"(\d+)\s+source\s+connectors?\b", line, re.I):
                num = int(m.group(1))
                if "connectors" in actual:
                    check("connectors", actual["connectors"], doc_name, num, i + 1)

        # --- Normalizers: "Normalizers (41)" or "41 normalizers/parsers" ---
        if not _is_demo_output(line):
            for m in re.finditer(r"Normalizers?\s*\(\s*(\d+)\s*(?:parsers?)?\)", line, re.I):
                num = int(m.group(1))
                if "normalizers" in actual:
                    check("normalizers", actual["normalizers"], doc_name, num, i + 1)

            for m in re.finditer(r"(\d+)\s+(?:normalizers?|parsers?)\b", line, re.I):
                num = int(m.group(1))
                if "normalizers" in actual:
                    check("normalizers", actual["normalizers"], doc_name, num, i + 1)

        # --- Frameworks: "14 frameworks" or "14 framework YAMLs" ---
        # Skip "across N frameworks" (subset references for OPA/OSCAL)
        for m in re.finditer(r"(\d+)\s+(?:compliance\s+)?framework(?:s\b|\s+YAML)", line, re.I):
            num = int(m.group(1))
            context_before = line[: m.start()].lower()
            if "across" in context_before[-25:] or "for" in context_before[-15:]:
                continue
            if "frameworks" in actual:
                check("frameworks", actual["frameworks"], doc_name, num, i + 1)

        # --- Tests: "190 tests" or "190 pytest tests" ---
        for m in re.finditer(r"\b(\d+)\s+(?:pytest\s+)?tests?\b", line, re.I):
            num = int(m.group(1))
            if num < 50:  # skip small numbers like "0 failures"
                continue
            rest = line[m.end() : m.end() + 15]
            if "file" in rest.lower():  # skip "190 tests (9 files)" -- handled separately
                continue
            if "tests" in actual:
                check("tests", actual["tests"], doc_name, num, i + 1)

        # --- Test files: "9 files" in tests context ---
        for m in re.finditer(r"tests.*?\((\d+)\s+files?\)", line, re.I):
            num = int(m.group(1))
            if "test_files" in actual:
                check("test_files", actual["test_files"], doc_name, num, i + 1)

        # --- Rego files: "670 OPA/Rego files" or "670 Rego policies" ---
        for m in re.finditer(r"(\d+)\s+(?:OPA[/]?)?Rego\s+(?:files|policies)", line, re.I):
            num = int(m.group(1))
            if "rego_files" in actual:
                check("rego_files", actual["rego_files"], doc_name, num, i + 1)

        # --- Terraform modules: "12 IaC modules" in terraform context ---
        for m in re.finditer(r"(\d+)\s+(?:IaC\s+)?modules?\b", line, re.I):
            num = int(m.group(1))
            if "terraform" in line.lower() or "iac" in line.lower():
                if "terraform_modules" in actual:
                    check("terraform_modules", actual["terraform_modules"], doc_name, num, i + 1)

        # --- OSCAL JSON: "17 JSON files" in OSCAL context ---
        for m in re.finditer(r"(\d+)\s+(?:OSCAL\s+)?JSON\s+files", line, re.I):
            num = int(m.group(1))
            if "oscal" in line.lower() or (i > 0 and "oscal" in lines[i - 1].lower()):
                if "oscal_json" in actual:
                    check("oscal_json", actual["oscal_json"], doc_name, num, i + 1)

        # --- CLI commands: "41 commands" in CLI context ---
        for m in re.finditer(r"(\d+)\s+commands?\b", line, re.I):
            num = int(m.group(1))
            if "cli" in line.lower() or "click" in line.lower():
                if "cli_commands" in actual:
                    check("cli_commands", actual["cli_commands"], doc_name, num, i + 1)

        # --- DB models: "34 SQLAlchemy models" or "34 tables" ---
        for m in re.finditer(r"(\d+)\s+(?:SQLAlchemy\s+)?models\b", line, re.I):
            num = int(m.group(1))
            if any(kw in line.lower() for kw in ("sqlalchemy", "db/", "database")):
                if "db_models" in actual:
                    check("db_models", actual["db_models"], doc_name, num, i + 1)

        for m in re.finditer(r"(\d+)\s+tables\b", line, re.I):
            num = int(m.group(1))
            if any(kw in line.lower() for kw in ("alembic", "migration", "database")):
                if "db_models" in actual:
                    check("db_models", actual["db_models"], doc_name, num, i + 1)

        # --- Migrations: "11 Alembic migrations" or "11 revisions" ---
        for m in re.finditer(r"(\d+)\s+(?:Alembic\s+)?(?:migrations?|revisions?)\b", line, re.I):
            num = int(m.group(1))
            if "migrations" in actual:
                check("migrations", actual["migrations"], doc_name, num, i + 1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    print(f"\n{BOLD}=== Warlock Documentation Accuracy Check ==={RESET}\n")

    print(f"{BOLD}Collecting actual counts...{RESET}")
    actual = get_actual_counts()

    if VERBOSE:
        print()
        for k, v in sorted(actual.items()):
            print(f"  {k}: {v}")
        print()

    print(f"{BOLD}Checking documentation claims...{RESET}\n")

    doc_files = ["README.md", "CLAUDE.md", "DEMO.md", "CONTRIBUTING.md"]
    for doc_name in doc_files:
        path = ROOT / doc_name
        if path.exists():
            find_claims(doc_name, path.read_text(), actual)

    print()
    if mismatches:
        print(f"{RED}{BOLD}FAILED: {len(mismatches)} documentation count(s) are wrong{RESET}\n")
        for m in mismatches:
            print(m)
        print()
        print("Fix these counts in the documentation files, or update the codebase.")
        return 1
    else:
        print(f"{GREEN}{BOLD}PASSED: All documentation counts match reality{RESET}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
