"""Verify API routers use repository pattern, not raw session.query()."""

import ast
import pytest
from pathlib import Path

ROUTERS_DIR = Path("warlock/api/routers")

# These routers should have zero raw session.query() calls after migration
MIGRATED_ROUTERS = [
    "compliance.py",
    "risk.py",
    "admin.py",
    "export.py",
    "pipeline.py",
]

# These routers are pending migration (none remaining)
PENDING_MIGRATION_ROUTERS: list[str] = []

# These routers are allowed to keep raw session.query() (OLTP-only permanently)
EXEMPT_ROUTERS = ["auth_routes.py", "health.py", "ai_routes.py", "governance.py"]


class TestRepositoryMigration:
    @pytest.mark.parametrize("router_file", MIGRATED_ROUTERS)
    def test_no_raw_db_query(self, router_file):
        """Verify migrated routers don't use raw db.query() — use repository methods."""
        source = (ROUTERS_DIR / router_file).read_text()
        tree = ast.parse(source)
        raw_query_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "query" and isinstance(node.func.value, ast.Name):
                    if node.func.value.id in ("db", "session"):
                        raw_query_calls.append(node.lineno)
        assert len(raw_query_calls) == 0, (
            f"{router_file} has {len(raw_query_calls)} raw db.query()/session.query() calls "
            f"at lines {raw_query_calls[:10]}. Use repository methods instead.\n"
            + "\n".join(f"  line {ln}" for ln in raw_query_calls[:5])
        )
