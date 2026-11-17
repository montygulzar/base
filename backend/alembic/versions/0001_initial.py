"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-11-17
"""
from alembic import op
from app.db import Base
from app import models  # noqa: F401

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Use SQLAlchemy metadata to create every table declared by the app.
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade():
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
