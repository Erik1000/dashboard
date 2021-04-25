"""add model for security key metadata

Revision ID: 28454a4f3f6d
Revises: 3b37a75d0aab
Create Date: 2021-04-24 20:09:40.046564

"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "28454a4f3f6d"
down_revision = "3b37a75d0aab"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "webauthn_entries",
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("nickname", sa.Unicode(), nullable=True),
        sa.Column("user_uuid", postgresql.UUID(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_uuid"],
            ["dashboard_users.user_uuid"],
        ),
        sa.PrimaryKeyConstraint("credential_id"),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("webauthn_entries")
    # ### end Alembic commands ###