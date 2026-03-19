# Known Alembic Drift

## FK ondelete differences on SQLite

**Status:** Expected and intentional
**Affected tables:** raw_events, findings, control_mappings, control_results, issues, issue_comments
**Introduced:** M-10 fix (FK cascade rules)

### What Alembic reports

`alembic check` detects that the SQLAlchemy models define `ondelete="CASCADE"` and `ondelete="SET NULL"` on foreign keys, but the SQLite database schema does not include these clauses in the DDL.

### Why this is expected

SQLite does not support `ALTER TABLE ... ADD CONSTRAINT ... ON DELETE CASCADE`. FK cascade behavior on SQLite is controlled at runtime via `PRAGMA foreign_keys=ON`, which is set by the engine event listener in `warlock/db/engine.py` (M-1 fix). The `ondelete` clauses in the models are for PostgreSQL, where they are applied through DDL during table creation or migration.

### Specific FKs affected

| Table | Column | ondelete |
|---|---|---|
| `raw_events` | `connector_run_id` | CASCADE |
| `findings` | `raw_event_id` | CASCADE |
| `findings` | `system_profile_id` | SET NULL |
| `control_mappings` | `finding_id` | CASCADE |
| `control_results` | `finding_id` | CASCADE |
| `control_results` | `control_mapping_id` | CASCADE |
| `control_results` | `system_profile_id` | SET NULL |
| `issue_comments` | `issue_id` | CASCADE |
| `issues` | `poam_id` | SET NULL |

### Resolution path

This drift resolves automatically when running on PostgreSQL. The initial migration for PostgreSQL deployment should be generated against a PostgreSQL database, which will include the `ondelete` clauses in the DDL.

### How to verify on SQLite

The cascade behavior is enforced at runtime. To verify:
```python
from warlock.db.engine import get_engine
from sqlalchemy import text
with get_engine().connect() as conn:
    result = conn.execute(text("PRAGMA foreign_keys"))
    assert result.scalar() == 1  # FK enforcement is ON
```
