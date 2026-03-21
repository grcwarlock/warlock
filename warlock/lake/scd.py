"""SCD Type 2 (Slowly Changing Dimension) management.

When a dimension record changes, the previous version is closed
(valid_to set to change date, is_current set to false) and a new
version is appended (valid_from set to change date, is_current true).

Used by entity dimension writers (resources, systems, personnel,
vendors, data_silos, software_components) to maintain history.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


def apply_scd_type2(
    existing: list[dict],
    incoming: list[dict],
    key_fields: list[str],
    change_date: str | None = None,
    compare_fields: list[str] | None = None,
) -> list[dict]:
    """Apply SCD Type 2 logic to dimension records.

    Args:
        existing: Current dimension records (with valid_from, valid_to, is_current)
        incoming: New records to merge
        key_fields: Fields that identify the same entity (e.g., ["id"])
        change_date: Date string for version changes (default: today UTC)
        compare_fields: Fields to compare for changes. If None, compares all
                       fields except valid_from, valid_to, is_current, run_id.

    Returns:
        Merged list with closed old versions and new current versions.
    """
    if not change_date:
        change_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    scd_meta_fields = {"valid_from", "valid_to", "is_current", "run_id"}

    # Index existing current records by key
    existing_by_key: dict[tuple, dict] = {}
    result: list[dict] = []

    for record in existing:
        key = tuple(record.get(f, "") for f in key_fields)
        if str(record.get("is_current", "")).lower() in ("true", "1", "yes"):
            existing_by_key[key] = record
        result.append(dict(record))  # Keep all existing records (including closed ones)

    # Process incoming records
    for record in incoming:
        key = tuple(record.get(f, "") for f in key_fields)
        current = existing_by_key.get(key)

        if current is None:
            # New entity — insert as current
            new_record = dict(record)
            new_record["valid_from"] = record.get("valid_from", change_date)
            new_record["valid_to"] = record.get("valid_to", "9999-12-31")
            new_record["is_current"] = "true"
            result.append(new_record)
            log.debug("SCD2: New entity %s", key)
        else:
            # Existing entity — check for changes
            if compare_fields:
                fields_to_check = compare_fields
            else:
                fields_to_check = [f for f in record if f not in scd_meta_fields and f not in key_fields]

            changed = any(
                str(record.get(f, "")) != str(current.get(f, ""))
                for f in fields_to_check
            )

            if changed:
                # Close the current version in result
                for r in result:
                    r_key = tuple(r.get(f, "") for f in key_fields)
                    if r_key == key and str(r.get("is_current", "")).lower() in ("true", "1", "yes"):
                        r["valid_to"] = change_date
                        r["is_current"] = "false"
                        break

                # Add new version
                new_record = dict(record)
                new_record["valid_from"] = change_date
                new_record["valid_to"] = "9999-12-31"
                new_record["is_current"] = "true"
                result.append(new_record)
                log.debug("SCD2: Changed entity %s", key)
            else:
                log.debug("SCD2: No change for entity %s", key)

    return result
