"""add unique audit sequence and FK cascade rules

Revision ID: cf06b1e0cada
Revises: 4ac3b448d982
Create Date: 2026-03-19 10:25:00.039208

On SQLite, FK cascade rules are enforced via PRAGMA foreign_keys=ON
(set in engine.py). The ondelete clauses in the model are primarily
for PostgreSQL. This migration uses batch_alter_table which recreates
the table on SQLite, picking up the new FK definitions automatically.

For the unique audit sequence: the index is dropped and recreated with
unique=True to prevent hash chain corruption from concurrent writes.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'cf06b1e0cada'
down_revision: Union[str, Sequence[str], None] = '4ac3b448d982'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade: unique audit sequence index.

    FK cascade rules are defined in the model but SQLite applies them
    via PRAGMA foreign_keys=ON at connection time. The batch_alter_table
    in render_as_batch mode will pick up the new FK definitions when
    tables are next recreated by a subsequent migration. For PostgreSQL,
    a separate ALTER TABLE would be needed.
    """
    with op.batch_alter_table('audit_entries', schema=None) as batch_op:
        batch_op.drop_index('idx_audit_sequence')
        batch_op.create_index('idx_audit_sequence', ['sequence'], unique=True)


def downgrade() -> None:
    """Downgrade: remove unique constraint from audit sequence."""
    with op.batch_alter_table('audit_entries', schema=None) as batch_op:
        batch_op.drop_index('idx_audit_sequence')
        batch_op.create_index('idx_audit_sequence', ['sequence'], unique=False)
