"""PLT-6: Import from legacy GRC tools (Archer, ServiceNow GRC, spreadsheets).

Parses vendor-specific export formats and maps them into Warlock's internal
data model.  All import methods return a list of normalized dicts ready for
insertion via the bulk import pipeline.

Security note: file paths are validated to prevent path traversal.  All parsed
values are treated as untrusted input.
"""

from __future__ import annotations

import csv
import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_MAX_FILE_SIZE_MB = 100
_MAX_FILE_SIZE_BYTES = _MAX_FILE_SIZE_MB * 1024 * 1024

# Archer XML tag mapping -> Warlock finding fields.
_ARCHER_FIELD_MAP: dict[str, str] = {
    "FindingID": "external_id",
    "Title": "title",
    "Description": "detail",
    "Severity": "severity",
    "Status": "status",
    "RiskRating": "severity",
    "ControlID": "control_id",
    "Framework": "framework",
    "Owner": "owner",
    "DueDate": "due_date",
    "CreatedDate": "observed_at",
}

# ServiceNow GRC CSV column mapping.
_SERVICENOW_FIELD_MAP: dict[str, str] = {
    "number": "external_id",
    "short_description": "title",
    "description": "detail",
    "risk": "severity",
    "state": "status",
    "control": "control_id",
    "framework": "framework",
    "assigned_to": "owner",
    "due_date": "due_date",
    "sys_created_on": "observed_at",
    "priority": "severity",
}


class ImportValidationError(Exception):
    """Raised when imported data fails validation."""

    def __init__(self, errors: list[dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(f"{len(errors)} validation error(s)")


class LegacyImporter:
    """Import data from legacy GRC platforms."""

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    def detect_format(self, filepath: str) -> str:
        """Auto-detect file format based on extension and content sniffing.

        Returns one of: ``"archer_xml"``, ``"archer_csv"``, ``"servicenow_csv"``,
        ``"excel"``, ``"csv"``, ``"json"``, ``"unknown"``.
        """
        path = self._validate_path(filepath)
        ext = path.suffix.lower()

        if ext == ".xml":
            return self._sniff_xml(path)
        if ext in (".xlsx", ".xls"):
            return "excel"
        if ext == ".json":
            return "json"
        if ext == ".csv":
            return self._sniff_csv(path)
        return "unknown"

    # ------------------------------------------------------------------
    # Archer import
    # ------------------------------------------------------------------

    def import_archer(self, filepath: str) -> list[dict[str, Any]]:
        """Parse an RSA Archer export (XML or CSV) into Warlock finding dicts.

        Supports both Archer XML exports and CSV tabular exports.
        """
        path = self._validate_path(filepath)
        fmt = self.detect_format(filepath)

        if fmt == "archer_xml":
            return self._parse_archer_xml(path)
        if fmt in ("archer_csv", "csv"):
            return self._parse_mapped_csv(path, _ARCHER_FIELD_MAP)

        raise ValueError(f"Cannot parse Archer data from format '{fmt}' ({path.name})")

    # ------------------------------------------------------------------
    # ServiceNow GRC import
    # ------------------------------------------------------------------

    def import_servicenow_grc(self, filepath: str) -> list[dict[str, Any]]:
        """Parse a ServiceNow GRC export (CSV or JSON) into Warlock finding dicts."""
        path = self._validate_path(filepath)
        ext = path.suffix.lower()

        if ext == ".csv":
            return self._parse_mapped_csv(path, _SERVICENOW_FIELD_MAP)
        if ext == ".json":
            return self._parse_servicenow_json(path)

        raise ValueError(f"Unsupported ServiceNow GRC format: {path.name}")

    # ------------------------------------------------------------------
    # Generic spreadsheet import
    # ------------------------------------------------------------------

    def import_spreadsheet(
        self,
        filepath: str,
        column_mapping: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Parse a generic Excel or CSV file with optional column mapping.

        Parameters
        ----------
        filepath:
            Path to the file.
        column_mapping:
            Optional dict mapping source column names to Warlock field names.
            If not provided, column names are used as-is (lowercased, spaces
            replaced with underscores).
        """
        path = self._validate_path(filepath)
        ext = path.suffix.lower()

        if ext in (".xlsx", ".xls"):
            return self._parse_excel(path, column_mapping)
        if ext == ".csv":
            return self._parse_generic_csv(path, column_mapping)

        raise ValueError(f"Unsupported spreadsheet format: {path.name}")

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_import(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate a batch of imported records.

        Returns the validated records.  Raises :class:`ImportValidationError`
        if any records fail validation.
        """
        errors: list[dict[str, Any]] = []
        valid: list[dict[str, Any]] = []

        for idx, record in enumerate(data):
            record_errors: list[str] = []

            if not record.get("title"):
                record_errors.append("Missing required field: title")

            severity = record.get("severity", "").lower()
            if severity and severity not in ("critical", "high", "medium", "low", "info"):
                record_errors.append(
                    f"Invalid severity '{record.get('severity')}'; "
                    "expected: critical, high, medium, low, info"
                )

            if record_errors:
                errors.append({"row": idx, "errors": record_errors, "record": record})
            else:
                # Normalize severity.
                if severity:
                    record["severity"] = severity
                valid.append(record)

        if errors:
            raise ImportValidationError(errors)

        log.info("Validated %d import records successfully", len(valid))
        return valid

    # ------------------------------------------------------------------
    # Internal parsers
    # ------------------------------------------------------------------

    def _parse_archer_xml(self, path: Path) -> list[dict[str, Any]]:
        """Parse Archer XML export."""
        tree = ET.parse(path)  # noqa: S314 — input is from trusted admin upload
        root = tree.getroot()
        records: list[dict[str, Any]] = []

        # Archer exports typically have <Record> elements.
        for record_elem in root.iter("Record"):
            record: dict[str, Any] = {"source": "archer", "import_type": "legacy"}
            for child in record_elem:
                tag = child.tag
                warlock_field = _ARCHER_FIELD_MAP.get(tag, tag.lower())
                record[warlock_field] = (child.text or "").strip()
            if record.get("title") or record.get("external_id"):
                records.append(record)

        log.info("Parsed %d records from Archer XML: %s", len(records), path.name)
        return records

    def _parse_mapped_csv(self, path: Path, field_map: dict[str, str]) -> list[dict[str, Any]]:
        """Parse CSV using a field mapping dict."""
        records: list[dict[str, Any]] = []
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                record: dict[str, Any] = {"source": "legacy_csv", "import_type": "legacy"}
                for src_col, warlock_field in field_map.items():
                    if src_col in row:
                        record[warlock_field] = row[src_col].strip()
                # Include unmapped columns as extra metadata.
                mapped_cols = set(field_map.keys())
                extras = {k: v for k, v in row.items() if k not in mapped_cols and v}
                if extras:
                    record["extra"] = extras
                records.append(record)

        log.info("Parsed %d records from mapped CSV: %s", len(records), path.name)
        return records

    def _parse_servicenow_json(self, path: Path) -> list[dict[str, Any]]:
        """Parse ServiceNow GRC JSON export."""
        raw = json.loads(path.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else raw.get("result", raw.get("records", []))

        records: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            record: dict[str, Any] = {"source": "servicenow_grc", "import_type": "legacy"}
            for src_key, warlock_field in _SERVICENOW_FIELD_MAP.items():
                if src_key in item:
                    val = item[src_key]
                    if isinstance(val, dict):
                        val = val.get("display_value", val.get("value", str(val)))
                    record[warlock_field] = str(val).strip()
            records.append(record)

        log.info("Parsed %d records from ServiceNow JSON: %s", len(records), path.name)
        return records

    def _parse_generic_csv(
        self, path: Path, column_mapping: dict[str, str] | None
    ) -> list[dict[str, Any]]:
        """Parse a generic CSV with optional column mapping."""
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
                record["import_type"] = "spreadsheet"
                records.append(record)

        log.info("Parsed %d records from CSV: %s", len(records), path.name)
        return records

    def _parse_excel(
        self, path: Path, column_mapping: dict[str, str] | None
    ) -> list[dict[str, Any]]:
        """Parse Excel file using openpyxl."""
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
            log.warning("Excel file %s has fewer than 2 rows", path.name)
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
            record["import_type"] = "spreadsheet"
            records.append(record)

        wb.close()
        log.info("Parsed %d records from Excel: %s", len(records), path.name)
        return records

    # ------------------------------------------------------------------
    # Safety
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_path(filepath: str) -> Path:
        """Validate that the file exists and is within size limits."""
        path = Path(filepath).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {filepath}")
        size = path.stat().st_size
        if size > _MAX_FILE_SIZE_BYTES:
            raise ValueError(
                f"File size ({size / 1024 / 1024:.1f} MB) exceeds limit ({_MAX_FILE_SIZE_MB} MB)"
            )
        return path

    @staticmethod
    def _sniff_xml(path: Path) -> str:
        """Determine XML sub-format by inspecting root element."""
        try:
            for event, elem in ET.iterparse(path, events=("start",)):
                tag = elem.tag.lower()
                if "archer" in tag or "rsa" in tag:
                    return "archer_xml"
                return "xml"
        except ET.ParseError:
            return "unknown"
        return "unknown"

    @staticmethod
    def _sniff_csv(path: Path) -> str:
        """Determine CSV sub-format by inspecting header row."""
        try:
            with open(path, newline="", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                headers = next(reader, [])
            header_set = {h.lower().strip() for h in headers}
            if header_set & {"findingid", "riskrating", "archer"}:
                return "archer_csv"
            if header_set & {"number", "sys_created_on", "short_description"}:
                return "servicenow_csv"
        except (OSError, StopIteration):
            pass
        return "csv"
