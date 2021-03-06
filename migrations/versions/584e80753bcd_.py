"""empty message

Revision ID: 584e80753bcd
Revises: 905fc6d649cd
Create Date: 2018-10-02 11:33:34.182050

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '584e80753bcd'
down_revision = '905fc6d649cd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('roles', sa.Column('default', sa.Boolean(), nullable=True))
    op.add_column('roles', sa.Column('permissions', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_roles_default'), 'roles', ['default'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_roles_default'), table_name='roles')
    op.drop_column('roles', 'permissions')
    op.drop_column('roles', 'default')
    # ### end Alembic commands ###
