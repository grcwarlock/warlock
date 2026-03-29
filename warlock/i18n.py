"""Internationalization (i18n) support for Warlock.

Provides a simple translation function ``_()`` and locale management.
Default locale is ``en_US``. New locales can be added by creating JSON
files in the ``locales/`` directory.

Locale files are JSON with flat key-value pairs:
    {"greeting": "Hello", "compliant": "Compliant", ...}
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Default locale
_DEFAULT_LOCALE = "en_US"
_current_locale = _DEFAULT_LOCALE

# Locale directory (alongside this file)
_LOCALE_DIR = Path(__file__).parent / "locales"

# In-memory translation cache: locale -> {key: translation}
_translations: dict[str, dict[str, str]] = {}

# Built-in en_US strings (always available, no file needed)
_BUILTIN_EN_US: dict[str, str] = {
    "compliant": "Compliant",
    "non_compliant": "Non-Compliant",
    "partial": "Partial",
    "not_assessed": "Not Assessed",
    "not_applicable": "Not Applicable",
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "risk_score": "Risk Score",
    "framework": "Framework",
    "control": "Control",
    "finding": "Finding",
    "evidence": "Evidence",
    "policy": "Policy",
    "vendor": "Vendor",
    "system": "System",
    "pipeline_running": "Pipeline running...",
    "no_data_found": "No data found.",
    "compliant_status": "Compliant",
    "assessment_complete": "Assessment complete.",
    "export_complete": "Export complete.",
    "error_occurred": "An error occurred.",
}


def _load_locale(locale: str) -> dict[str, str]:
    """Load translations for a locale from JSON file."""
    if locale == "en_US":
        return dict(_BUILTIN_EN_US)

    locale_file = _LOCALE_DIR / f"{locale}.json"
    if not locale_file.exists():
        log.warning("Locale file not found: %s -- falling back to en_US", locale_file)
        return dict(_BUILTIN_EN_US)

    try:
        with open(locale_file) as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            log.warning("Invalid locale file format: %s", locale_file)
            return dict(_BUILTIN_EN_US)
        # Merge with en_US as fallback for missing keys
        merged = dict(_BUILTIN_EN_US)
        merged.update(data)
        return merged
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to load locale %s: %s", locale, exc)
        return dict(_BUILTIN_EN_US)


def get_locale() -> str:
    """Return the current active locale."""
    return _current_locale


def set_locale(locale: str) -> None:
    """Set the active locale.

    Loads translations from the locale file if not already cached.
    Falls back to en_US if the locale file is not found.
    """
    global _current_locale
    _current_locale = locale
    if locale not in _translations:
        _translations[locale] = _load_locale(locale)
    log.info("Locale set to %s", locale)


def available_locales() -> list[str]:
    """List available locales (en_US + any .json files in locales dir)."""
    locales = ["en_US"]
    if _LOCALE_DIR.exists():
        for f in sorted(_LOCALE_DIR.glob("*.json")):
            name = f.stem
            if name not in locales:
                locales.append(name)
    return locales


def _(key: str, **kwargs: Any) -> str:
    """Translate a key using the current locale.

    Supports format string interpolation via kwargs:
        _("greeting", name="World") -> "Hello, World"

    Falls back to the key itself if no translation exists.
    """
    locale = _current_locale
    if locale not in _translations:
        _translations[locale] = _load_locale(locale)

    text = _translations[locale].get(key, key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError):
            return text
    return text


# Initialize default locale on import
set_locale(os.environ.get("WLK_LOCALE", _DEFAULT_LOCALE))
