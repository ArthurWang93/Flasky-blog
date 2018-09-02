"""second migration

Revision ID: 1a73ec1d57a1
Revises: 456a945560f6
Create Date: 2018-08-09 21:30:16.790222

"""

# revision identifiers, used by Alembic.
revision = '1a73ec1d57a1'
down_revision = '456a945560f6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('confirmed', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'confirmed')
    # ### end Alembic commands ###
