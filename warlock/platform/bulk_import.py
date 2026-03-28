"""PLT-7: Generic bulk import for findings, vendors, personnel, and controls.

Supports CSV, JSON, and Excel formats.  All imports go through validation
before any database writes.  A preview mode lets callers inspect what would
be imported without committing.
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

_SUPPORTED_FORMATS = frozenset({"csv", "json", "excel"})

# Required fields per entity type.
_REQUIRED_FIELDS: dict[str, list[str]] = {
    "finding": ["title", "severity"],
    "vendor": ["name"],
    "personnel": ["email", "full_name"],
    "control": ["control_id", "framework"],
}

# Allowed severity values for findings.
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

# Allowed vendor tiers.
_VALID_VENDOR_TIERS = frozenset({"critical", "high", "medium", "low"})


class BulkImportError(Exception):
    """Raised when bulk import validation fails."""

    def __init__(self, errors: list[dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(f"{len(errors)} validation error(s) in bulk import")


class BulkImporter:
    """Bulk import manager for Warlock entities."""

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Entity-specific imports
    # ------------------------------------------------------------------

    def import_findings(
        self,
        filepath: str,
        format: str,  # noqa: A002
        *,
        column_mapping: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Bulk import findings from a file.

        Returns validated finding dicts ready for database insertion.
        """
        records = self._load_file(filepath, format, column_mapping)
        validated = self.validate_batch(records, "finding")
        log.info("Imported %d findings from %s", len(validated), filepath)
        return validated

    def import_vendors(
        self,
        filepath: str,
        format: str,  # noqa: A002
        *,
        column_mapping: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Bulk import vendors from a file."""
        records = self._load_file(filepath, format, column_mapping)
        validated = self.validate_batch(records, "vendor")
        log.info("Imported %d vendors from %s", len(validated), filepath)
        return validated

    def import_personnel(
        self,
        filepath: str,
        format: str,  # noqa: A002
        *,
        column_mapping: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Bulk import personnel records from a file."""
        records = self._load_file(filepath, format, column_mapping)
        validated = self.validate_batch(records, "personnel")
        log.info("Imported %d personnel from %s", len(validated), filepath)
        return validated

    def import_controls(
        self,
        filepath: str,
        format: str,  # noqa: A002
        *,
        column_mapping: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Bulk import control definitions from a file."""
        records = self._load_file(filepath, format, column_mapping)
        validated = self.validate_batch(records, "control")
        log.info("Imported %d controls from %s", len(validated), filepath)
        return validated

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_batch(
        self,
        records: list[dict[str, Any]],
        entity_type: str,
    ) -> list[dict[str, Any]]:
        """Validate a batch of records against the schema for *entity_type*.

        Returns the validated (and normalized) records.  Raises
        :class:`BulkImportError` if any records fail validation.

        Parameters
        ----------
        records:
            List of dicts to validate.
        entity_type:
            One of ``"finding"``, ``"vendor"``, ``"personnel"``, ``"control"``.
        """
        if entity_type not in _REQUIRED_FIELDS:
            raise ValueError(
                f"Unknown entity type '{entity_type}'; expected one of: {sorted(_REQUIRED_FIELDS)}"
            )

        required = _REQUIRED_FIELDS[entity_type]
        errors: list[dict[str, Any]] = []
        valid: list[dict[str, Any]] = []

        for idx, record in enumerate(records):
            record_errors: list[str] = []

            # Check required fields.
            for field in required:
                val = record.get(field)
                if not val or (isinstance(val, str) and not val.strip()):
                    record_errors.append(f"Missing required field: {field}")

            # Entity-specific validation.
            if entity_type == "finding":
                record_errors.extend(self._validate_finding(record))
            elif entity_type == "vendor":
                record_errors.extend(self._validate_vendor(record))
            elif entity_type == "personnel":
                record_errors.extend(self._validate_personnel(record))

            if record_errors:
                errors.append({"row": idx, "errors": record_errors, "record": record})
            else:
                valid.append(self._normalize_record(record, entity_type))

        if errors:
            raise BulkImportError(errors)

        return valid

    # ------------------------------------------------------------------
    # Preview
    # ------------------------------------------------------------------

    def preview(
        self,
        filepath: str,
        format: str,  # noqa: A002
        limit: int = 5,
        *,
        column_mapping: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Show a preview of what would be imported without committing.

        Returns up to *limit* records parsed from the file.
        """
        records = self._load_file(filepath, format, column_mapping)
        return records[:limit]

    # ------------------------------------------------------------------
    # File loading
    # ------------------------------------------------------------------

    def _load_file(
        self,
        filepath: str,
        fmt: str,
        column_mapping: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Load records from a file in the given format."""
        fmt = fmt.lower()
        if fmt not in _SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported format '{fmt}'; expected one of: {sorted(_SUPPORTED_FORMATS)}"
            )

        path = self._validate_path(filepath)

        if fmt == "csv":
            return self._load_csv(path, column_mapping)
        if fmt == "json":
            return self._load_json(path, column_mapping)
        if fmt == "excel":
            return self._load_excel(path, column_mapping)

        raise ValueError(f"Unsupported format: {fmt}")

    def _load_csv(self, path: Path, column_mapping: dict[str, str] | None) -> list[dict[str, Any]]:
        """Load CSV file into list of dicts."""
        records: list[dict[str, Any]] = []
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if column_mapping:
                    record = {
                        warlock_field: row.get(src_col, "").strip()
                        for src_col, warlock_field in column_mapping.items()
                    }
                else:
                    record = {
                        k.lower().replace(" ", "_"): v.strip()
                        for k, v in row.items()
                        if k is not None
                    }
                records.append(record)
        return records

    def _load_json(self, path: Path, column_mapping: dict[str, str] | None) -> list[dict[str, Any]]:
        """Load JSON file (array of objects or object with 'records' key)."""
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            raw = raw.get("records", raw.get("data", raw.get("items", [])))
        if not isinstance(raw, list):
            raise ValueError("JSON file must contain an array of objects or a 'records' key")

        records: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            if column_mapping:
                record = {
                    warlock_field: item.get(src_col, "")
                    for src_col, warlock_field in column_mapping.items()
                }
            else:
                record = {k.lower().replace(" ", "_"): v for k, v in item.items()}
            records.append(record)
        return records

    def _load_excel(
        self, path: Path, column_mapping: dict[str, str] | None
    ) -> list[dict[str, Any]]:
        """Load Excel file using openpyxl."""
        try:
            import openpyxl
        except ImportError:
            raise ImportError(
                "openpyxl is required for Excel import. Install with: pip install openpyxl"
            ) from None

        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        ws = wb.active
        if ws is None:
            raise ValueError(f"No active worksheet in {path.name}")

        rows = list(ws.iter_rows(values_only=True))
        if len(rows) < 2:
            wb.close()
            return []

        headers = [str(h).strip() if h else f"col_{i}" for i, h in enumerate(rows[0])]
        records: list[dict[str, Any]] = []

        for row in rows[1:]:
            raw = {headers[i]: (str(v).strip() if v is not None else "") for i, v in enumerate(row)}
            if column_mapping:
                record = {
                    warlock_field: raw.get(src_col, "")
                    for src_col, warlock_field in column_mapping.items()
                }
            else:
                record = {k.lower().replace(" ", "_"): v for k, v in raw.items()}
            records.append(record)

        wb.close()
        return records

    # ------------------------------------------------------------------
    # Entity-specific validators
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_finding(record: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        severity = str(record.get("severity", "")).lower()
        if severity and severity not in _VALID_SEVERITIES:
            errors.append(
                f"Invalid severity '{record.get('severity')}'; "
                f"expected one of: {sorted(_VALID_SEVERITIES)}"
            )
        return errors

    @staticmethod
    def _validate_vendor(record: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        tier = record.get("tier", "")
        if tier and str(tier).lower() not in _VALID_VENDOR_TIERS:
            errors.append(
                f"Invalid vendor tier '{tier}'; expected one of: {sorted(_VALID_VENDOR_TIERS)}"
            )
        return errors

    @staticmethod
    def _validate_personnel(record: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        email = record.get("email", "")
        if email and "@" not in str(email):
            errors.append(f"Invalid email address: {email}")
        return errors

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_record(record: dict[str, Any], entity_type: str) -> dict[str, Any]:
        """Normalize field values (lowercase severity, trim strings, etc.)."""
        normalized = {}
        for k, v in record.items():
            if isinstance(v, str):
                v = v.strip()
            normalized[k] = v

        if entity_type == "finding" and "severity" in normalized:
            normalized["severity"] = str(normalized["severity"]).lower()
        if entity_type == "vendor" and "tier" in normalized:
            normalized["tier"] = str(normalized["tier"]).lower()

        return normalized

    # ------------------------------------------------------------------
    # Persistence (STUB-008 fix: actually write to DB)
    # ------------------------------------------------------------------

    def persist_batch(
        self,
        session: "Session",
        records: list[dict[str, Any]],
        entity_type: str,
    ) -> dict[str, Any]:
        """Persist a validated batch of records to the database.

        Maps entity_type to the correct SQLAlchemy model and calls
        session.add() for each record.

        Args:
            session: SQLAlchemy session (caller manages commit).
            records: Validated and normalised record dicts.
            entity_type: One of finding, vendor, personnel, control.

        Returns:
            Dict with status, count of records persisted.
        """
        from warlock.db.models import Personnel, Vendor

        model_map: dict[str, type] = {
            "vendor": Vendor,
            "personnel": Personnel,
        }

        model_cls = model_map.get(entity_type)
        if model_cls is None:
            log.warning(
                "persist_batch: entity_type '%s' does not have a direct model mapping; "
                "returning records for caller to handle",
                entity_type,
            )
            return {"status": "unsupported_entity", "count": len(records)}

        persisted = 0
        for record in records:
            # Filter to only columns that exist on the model
            valid_cols = {c.key for c in model_cls.__table__.columns}
            filtered = {k: v for k, v in record.items() if k in valid_cols}
            obj = model_cls(**filtered)
            session.add(obj)
            persisted += 1

        session.flush()
        log.info("Batch persisted: %d %s record(s)", persisted, entity_type)
        return {"status": "success", "count": persisted}

    # ------------------------------------------------------------------
    # Safety
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_path(filepath: str) -> Path:
        path = Path(filepath).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {filepath}")
        return path
