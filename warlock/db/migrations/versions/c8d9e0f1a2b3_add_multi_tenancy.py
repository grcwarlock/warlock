"""Add multi-tenancy: tenants table and tenant_id FK on all models.

Creates the ``tenants`` table, inserts the default system tenant, then adds
``tenant_id`` (String(36), FK → tenants.id) to every existing table.  Existing
rows are backfilled to the default tenant.

Revision ID: a1b2c3d4e5f6
Revises: f7a8b9c0d1e2
Create Date: 2026-03-28
"""

from alembic import op
import sqlalchemy as sa

revision = "c8d9e0f1a2b3"
down_revision = "f7a8b9c0d1e2"
branch_labels = None
depends_on = None

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000000"

# Every table that gets a tenant_id column (all models except tenants itself)
_TABLES = [
    "connector_runs",
    "raw_events",
    "findings",
    "control_mappings",
    "control_results",
    "audit_entries",
    "posture_snapshots",
    "users",
    "api_keys",
    "risk_analyses",
    "audit_engagements",
    "poams",
    "compensating_controls",
    "risk_acceptances",
    "issues",
    "issue_comments",
    "attestations",
    "audit_comments",
    "legal_holds",
    "trust_access_requests",
    "trust_documents",
    "system_profiles",
    "personnel",
    "questionnaire_templates",
    "questionnaires",
    "data_silos",
    "control_inheritances",
    "system_dependencies",
    "change_events",
    "compliance_drifts",
    "policy_overrides",
    "external_auditors",
    "auditor_engagement_assignments",
    "evidence_requests",
    "embeddings",
    "policies",
    "policy_history",
    "assets",
    "vendors",
    "watch_subscriptions",
    "escalation_policies",
    "saved_queries",
    "ip_allowlist",
    "risk_dependencies",
    "alerts",
    "remediations",
    "pipeline_runs",
]


def upgrade() -> None:
    # 1. Create tenants table
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("config_overrides", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_tenant_slug", "tenants", ["slug"], unique=True)
    op.create_index("idx_tenant_active", "tenants", ["is_active"])

    # 2. Insert default system tenant
    op.execute(
        sa.text(
            "INSERT INTO tenants (id, name, slug, is_active, created_at) "
            "VALUES (:id, :name, :slug, 1, :ts)"
        ).bindparams(
            id=DEFAULT_TENANT_ID,
            name="System",
            slug="system",
            ts="2026-01-01T00:00:00+00:00",
        )
    )

    # 3. Add tenant_id to all tables, backfill, add index.
    #    Some tables may not exist yet (created by later migrations or
    #    only via Base.metadata.create_all in dev). Skip gracefully.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    for table in _TABLES:
        if table not in existing_tables:
            continue
        with op.batch_alter_table(table) as batch_op:
            batch_op.add_column(
                sa.Column("tenant_id", sa.String(36), nullable=True),
            )
        # Backfill existing rows to default tenant
        op.execute(
            sa.text(f'UPDATE "{table}" SET tenant_id = :tid WHERE tenant_id IS NULL').bindparams(
                tid=DEFAULT_TENANT_ID,
            )
        )
        # Now make non-nullable and add FK + index
        with op.batch_alter_table(table) as batch_op:
            batch_op.alter_column("tenant_id", nullable=False)
            batch_op.create_index(f"idx_{table}_tenant_id", ["tenant_id"])
            batch_op.create_foreign_key(
                f"fk_{table}_tenant_id",
                "tenants",
                ["tenant_id"],
                ["id"],
                ondelete="CASCADE",
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    for table in reversed(_TABLES):
        if table not in existing_tables:
            continue
        with op.batch_alter_table(table) as batch_op:
            batch_op.drop_constraint(f"fk_{table}_tenant_id", type_="foreignkey")
            batch_op.drop_index(f"idx_{table}_tenant_id")
            batch_op.drop_column("tenant_id")

    op.drop_index("idx_tenant_active", table_name="tenants")
    op.drop_index("idx_tenant_slug", table_name="tenants")
    op.drop_table("tenants")
