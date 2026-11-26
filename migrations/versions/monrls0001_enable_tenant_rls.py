"""Add RLS policies to monitoring tables.

Revision ID: monrls0001
Revises: 174791a8fd33
"""

from __future__ import annotations

from alembic import op

revision = "monrls0001"
down_revision = "174791a8fd33"
branch_labels = None
depends_on = None

TABLES = (
    "devices",
    "monitoring_sessions",
    "screenshots",
    "activity_heartbeats",
    "deletion_audit",
    "screenshot_views",
    "device_commands",
)

POLICY = (
    "(nullif(current_setting('app.tenant_id', true), '') IS NULL OR "
    "tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)"
)


def upgrade() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({POLICY}) WITH CHECK ({POLICY})"
        )


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
