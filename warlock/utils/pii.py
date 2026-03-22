"""PII detection and pseudonymization for normalizer output.

Scans FindingData fields for personally identifiable information (emails,
names, phone numbers, SSNs) and replaces them with deterministic hashed
pseudonyms. The goal: downstream consumers know *whether* PII was present,
but never see the PII itself.

Usage::

    from warlock.utils.pii import scrub_finding

    finding = normalizer.normalize(raw_event)
    clean = scrub_finding(finding)   # pii_detected=True if anything was found
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(
    r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)

_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_EMAIL_RE, "email"),
    (_SSN_RE, "ssn"),
    (_PHONE_RE, "phone"),
]

# Field keys that are known to contain PII values.  When a dict key matches
# one of these (case-insensitive), the value is pseudonymized regardless of
# whether it matches a regex pattern.
_PII_FIELD_KEYS: set[str] = {
    "email",
    "work_email",
    "user_email",
    "actor_email",
    "useremail",
    "user_name",
    "display_name",
    "actor_name",
    "supervisor",
    "assigned_to",
    "displayname",
    "fullname",
    "full_name",
    "first_name",
    "last_name",
    "firstname",
    "lastname",
}

# Detail keys whose values are raw payload dumps (entire API responses).
# These are removed entirely — they add no structured value and are the
# biggest PII vector.
_RAW_DUMP_KEYS: set[str] = {
    "event",
    "issue",
    "project",
    "user",
    "alert",
    "response",
    "record",
    "entry",
    "result",
    "item",
    "log",
    "finding",
    "member",
    "employee",
}


# ---------------------------------------------------------------------------
# Pseudonymization
# ---------------------------------------------------------------------------


def pseudonymize(value: str) -> str:
    """Replace a PII value with a deterministic, non-reversible pseudonym.

    Same input always produces the same output, so you can correlate across
    findings without knowing the original value.

    >>> pseudonymize("jane@company.com")
    'person:a1b2c3d4'
    """
    digest = hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()
    return f"person:{digest[:8]}"


# ---------------------------------------------------------------------------
# String-level scrubbing
# ---------------------------------------------------------------------------


def scrub_string(value: str) -> tuple[str, bool]:
    """Replace PII patterns in a free-text string.

    Returns (scrubbed_string, pii_was_found).
    """
    found = False
    result = value
    for pattern, _label in _PII_PATTERNS:
        matches = pattern.findall(result)
        for match in matches:
            result = result.replace(match, pseudonymize(match))
            found = True
    return result, found


# ---------------------------------------------------------------------------
# Dict-level scrubbing
# ---------------------------------------------------------------------------


def scrub_detail(detail: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Walk a detail dict and scrub PII.

    - Removes raw payload dump keys entirely
    - Pseudonymizes known PII field values
    - Scans remaining string values for PII patterns

    Returns (cleaned_dict, pii_was_found).
    """
    cleaned: dict[str, Any] = {}
    found = False

    for key, value in detail.items():
        key_lower = key.lower()

        # Drop raw payload dumps
        if key_lower in _RAW_DUMP_KEYS and isinstance(value, (dict, list)):
            found = True
            continue

        # Known PII field — pseudonymize the value
        if key_lower in _PII_FIELD_KEYS and isinstance(value, str) and value:
            cleaned[key] = pseudonymize(value)
            found = True
            continue

        # Recurse into nested dicts
        if isinstance(value, dict):
            scrubbed, nested_found = scrub_detail(value)
            cleaned[key] = scrubbed
            if nested_found:
                found = True
        # Recurse into lists
        elif isinstance(value, list):
            new_list = []
            for item in value:
                if isinstance(item, dict):
                    scrubbed, nested_found = scrub_detail(item)
                    new_list.append(scrubbed)
                    if nested_found:
                        found = True
                elif isinstance(item, str):
                    scrubbed_str, str_found = scrub_string(item)
                    new_list.append(scrubbed_str)
                    if str_found:
                        found = True
                else:
                    new_list.append(item)
            cleaned[key] = new_list
        # Scan plain string values for PII patterns
        elif isinstance(value, str):
            scrubbed_str, str_found = scrub_string(value)
            cleaned[key] = scrubbed_str
            if str_found:
                found = True
        else:
            cleaned[key] = value

    return cleaned, found


# ---------------------------------------------------------------------------
# Finding-level scrubbing (public API)
# ---------------------------------------------------------------------------


def scrub_finding(finding: Any) -> Any:
    """Scrub PII from a FindingData instance in place.

    - Pseudonymizes PII in ``title`` and ``resource_name``
    - Scrubs the ``detail`` dict
    - Sets ``pii_detected = True`` if anything was found

    Returns the same finding (mutated).
    """
    pii_found = False

    # Scrub title
    if finding.title:
        scrubbed, found = scrub_string(finding.title)
        if found:
            finding.title = scrubbed
            pii_found = True

    # Scrub resource_name
    if finding.resource_name:
        scrubbed, found = scrub_string(finding.resource_name)
        if found:
            finding.resource_name = scrubbed
            pii_found = True

    # Scrub detail dict (only if it's actually a dict)
    if finding.detail and isinstance(finding.detail, dict):
        scrubbed, found = scrub_detail(finding.detail)
        if found:
            finding.detail = scrubbed
            pii_found = True

    if pii_found:
        finding.pii_detected = True

    return finding
