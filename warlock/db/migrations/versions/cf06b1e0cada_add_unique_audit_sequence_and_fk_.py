"""add unique audit sequence and FK cascade rules

Revision ID: cf06b1e0cada
Revises: 4ac3b448d982
Create Date: 2026-03-19 10:25:00.039208

Applies two schema changes:
1. Unique constraint on audit_entries.sequence
2. FK ondelete rules on 6 pipeline tables

For SQLite: batch_alter_table recreates each table from scratch. We explicitly
drop old unnamed FK constraints and create new named ones with ondelete rules.
The column definitions are copied during the rebuild.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'cf06b1e0cada'
down_revision: Union[str, Sequence[str], None] = '4ac3b448d982'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Unique audit sequence index
    with op.batch_alter_table('audit_entries', schema=None) as batch_op:
        batch_op.drop_index('idx_audit_sequence')
        batch_op.create_index('idx_audit_sequence', ['sequence'], unique=True)

    # 2. raw_events: connector_run_id -> CASCADE
    with op.batch_alter_table('raw_events', schema=None,
                               naming_convention={"fk": "fk_%(table_name)s_%(column_0_name)s"}) as batch_op:
        batch_op.drop_constraint('fk_raw_events_connector_run_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_raw_events_connector_run_id', 'connector_runs',
                                     ['connector_run_id'], ['id'], ondelete='CASCADE')

    # 3. findings: raw_event_id -> CASCADE, system_profile_id -> SET NULL
    with op.batch_alter_table('findings', schema=None,
                               naming_convention={"fk": "fk_%(table_name)s_%(column_0_name)s"}) as batch_op:
        batch_op.drop_constraint('fk_findings_raw_event_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_findings_raw_event_id', 'raw_events',
                                     ['raw_event_id'], ['id'], ondelete='CASCADE')
        batch_op.drop_constraint('fk_findings_system', type_='foreignkey')
        batch_op.create_foreign_key('fk_findings_system', 'system_profiles',
                                     ['system_profile_id'], ['id'], ondelete='SET NULL')

    # 4. control_mappings: finding_id -> CASCADE
    with op.batch_alter_table('control_mappings', schema=None,
                               naming_convention={"fk": "fk_%(table_name)s_%(column_0_name)s"}) as batch_op:
        batch_op.drop_constraint('fk_control_mappings_finding_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_control_mappings_finding_id', 'findings',
                                     ['finding_id'], ['id'], ondelete='CASCADE')

    # 5. control_results: finding_id -> CASCADE, control_mapping_id -> CASCADE, system_profile_id -> SET NULL
    with op.batch_alter_table('control_results', schema=None,
                               naming_convention={"fk": "fk_%(table_name)s_%(column_0_name)s"}) as batch_op:
        batch_op.drop_constraint('fk_control_results_finding_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_control_results_finding_id', 'findings',
                                     ['finding_id'], ['id'], ondelete='CASCADE')
        batch_op.drop_constraint('fk_control_results_control_mapping_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_control_results_control_mapping_id', 'control_mappings',
                                     ['control_mapping_id'], ['id'], ondelete='CASCADE')
        batch_op.drop_constraint('fk_control_results_system', type_='foreignkey')
        batch_op.create_foreign_key('fk_control_results_system', 'system_profiles',
                                     ['system_profile_id'], ['id'], ondelete='SET NULL')

    # 6. issue_comments: issue_id -> CASCADE
    with op.batch_alter_table('issue_comments', schema=None,
                               naming_convention={"fk": "fk_%(table_name)s_%(column_0_name)s"}) as batch_op:
        batch_op.drop_constraint('fk_issue_comments_issue_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_issue_comments_issue_id', 'issues',
                                     ['issue_id'], ['id'], ondelete='CASCADE')

    # 7. issues: poam_id -> SET NULL
    with op.batch_alter_table('issues', schema=None,
                               naming_convention={"fk": "fk_%(table_name)s_%(column_0_name)s"}) as batch_op:
        batch_op.drop_constraint('fk_issues_poam_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_issues_poam_id', 'poams',
                                     ['poam_id'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    # Reverse unique audit sequence
    with op.batch_alter_table('audit_entries', schema=None) as batch_op:
        batch_op.drop_index('idx_audit_sequence')
        batch_op.create_index('idx_audit_sequence', ['sequence'], unique=False)

    # Reverse FK ondelete rules (remove ondelete, keep same constraint names)
    with op.batch_alter_table('raw_events', schema=None) as batch_op:
        batch_op.drop_constraint('fk_raw_events_connector_run_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_raw_events_connector_run_id', 'connector_runs',
                                     ['connector_run_id'], ['id'])

    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_constraint('fk_findings_raw_event_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_findings_raw_event_id', 'raw_events',
                                     ['raw_event_id'], ['id'])
        batch_op.drop_constraint('fk_findings_system', type_='foreignkey')
        batch_op.create_foreign_key('fk_findings_system', 'system_profiles',
                                     ['system_profile_id'], ['id'])

    with op.batch_alter_table('control_mappings', schema=None) as batch_op:
        batch_op.drop_constraint('fk_control_mappings_finding_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_control_mappings_finding_id', 'findings',
                                     ['finding_id'], ['id'])

    with op.batch_alter_table('control_results', schema=None) as batch_op:
        batch_op.drop_constraint('fk_control_results_finding_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_control_results_finding_id', 'findings',
                                     ['finding_id'], ['id'])
        batch_op.drop_constraint('fk_control_results_control_mapping_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_control_results_control_mapping_id', 'control_mappings',
                                     ['control_mapping_id'], ['id'])
        batch_op.drop_constraint('fk_control_results_system', type_='foreignkey')
        batch_op.create_foreign_key('fk_control_results_system', 'system_profiles',
                                     ['system_profile_id'], ['id'])

    with op.batch_alter_table('issue_comments', schema=None) as batch_op:
        batch_op.drop_constraint('fk_issue_comments_issue_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_issue_comments_issue_id', 'issues',
                                     ['issue_id'], ['id'])

    with op.batch_alter_table('issues', schema=None) as batch_op:
        batch_op.drop_constraint('fk_issues_poam_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_issues_poam_id', 'poams',
                                     ['poam_id'], ['id'])
