"""initial maintenance schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-07-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    from api.app.database import Base
    from api.app import models  # noqa: F401

    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    from api.app.database import Base
    from api.app import models  # noqa: F401

    Base.metadata.drop_all(bind=bind)

