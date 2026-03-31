"""Add trust_documents table for #45 SOC 2 report portal

Revision ID: d4e5f6a7b8c9
Revises: b1c2d3e4f5a6
Create Date: 2026-03-19 12:00:00.000000

Adds:
- trust_documents table with classification_tier (public/nda/contract),
  file_path, uploaded_by, uploaded_at, and metadata fields.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers
revision = "d4e5f6a7b8c9"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "trust_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("classification_tier", sa.String(20), nullable=False, server_default="nda"),
        sa.Column("file_path", sa.Text, nullable=False),
        sa.Column("content_type", sa.String(100), nullable=True),
        sa.Column("file_size_bytes", sa.Integer, nullable=True, server_default="0"),
        sa.Column("uploaded_by", sa.String(255), nullable=False),
        sa.Column(
            "uploaded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("is_active", sa.Boolean, nullable=True, server_default="1"),
    )

    op.create_index("idx_trust_doc_tier", "trust_documents", ["classification_tier"])
    op.create_index("idx_trust_doc_active", "trust_documents", ["is_active"])
    op.create_index("idx_trust_doc_uploaded", "trust_documents", ["uploaded_at"])


def downgrade() -> None:
    op.drop_index("idx_trust_doc_uploaded", table_name="trust_documents")
    op.drop_index("idx_trust_doc_active", table_name="trust_documents")
    op.drop_index("idx_trust_doc_tier", table_name="trust_documents")
    op.drop_table("trust_documents")
