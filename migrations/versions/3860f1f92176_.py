"""empty message

Revision ID: 3860f1f92176
Revises: 722f9530afa6
Create Date: 2022-12-24 22:02:53.915444

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3860f1f92176'
down_revision = '722f9530afa6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('_alembic_tmp_email')
    with op.batch_alter_table('email', schema=None) as batch_op:
        batch_op.drop_column('unread')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('email', schema=None) as batch_op:
        batch_op.add_column(sa.Column('unread', sa.BOOLEAN(), nullable=False))

    op.create_table('_alembic_tmp_email',
    sa.Column('emailid', sa.VARCHAR(), nullable=False),
    sa.Column('subject', sa.TEXT(), nullable=False),
    sa.Column('senderEmail', sa.VARCHAR(), nullable=False),
    sa.Column('dateReceived', sa.DATETIME(), nullable=False),
    sa.Column('sentimentvals', sa.BLOB(), nullable=False),
    sa.Column('recipient', sa.VARCHAR(), nullable=False),
    sa.PrimaryKeyConstraint('emailid', 'senderEmail')
    )
    # ### end Alembic commands ###
