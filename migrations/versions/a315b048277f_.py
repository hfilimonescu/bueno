"""empty message

Revision ID: a315b048277f
Revises: 
Create Date: 2023-12-06 09:15:12.984154

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a315b048277f'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('auth_permissions',
    sa.Column('name', sa.String(length=128), nullable=True),
    sa.Column('group', sa.String(length=128), nullable=True),
    sa.Column('parent', sa.String(length=128), nullable=True),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('auth_roles',
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('description', sa.String(length=128), nullable=False),
    sa.Column('group', sa.String(length=128), nullable=False),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('auth_users',
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=256), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('confirmed', sa.Boolean(), nullable=False),
    sa.Column('force_pwd_change', sa.Boolean(), nullable=False),
    sa.Column('failed_logins', sa.Integer(), nullable=False),
    sa.Column('type', sa.String(length=20), nullable=False),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('auth_users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_auth_users_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_auth_users_username'), ['username'], unique=True)

    op.create_table('auth_roles_permissions',
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.Column('permission_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['permission_id'], ['auth_permissions.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['role_id'], ['auth_roles.id'], ondelete='CASCADE')
    )
    op.create_table('auth_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('access_token', sa.String(length=64), nullable=False),
    sa.Column('access_expiration', sa.DateTime(), nullable=False),
    sa.Column('refresh_token', sa.String(length=64), nullable=False),
    sa.Column('refresh_expiration', sa.DateTime(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['auth_users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('auth_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_auth_tokens_access_token'), ['access_token'], unique=False)
        batch_op.create_index(batch_op.f('ix_auth_tokens_refresh_token'), ['refresh_token'], unique=False)
        batch_op.create_index(batch_op.f('ix_auth_tokens_user_id'), ['user_id'], unique=False)

    op.create_table('auth_users_roles',
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['auth_roles.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['auth_users.id'], ondelete='CASCADE')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('auth_users_roles')
    with op.batch_alter_table('auth_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_auth_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_auth_tokens_refresh_token'))
        batch_op.drop_index(batch_op.f('ix_auth_tokens_access_token'))

    op.drop_table('auth_tokens')
    op.drop_table('auth_roles_permissions')
    with op.batch_alter_table('auth_users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_auth_users_username'))
        batch_op.drop_index(batch_op.f('ix_auth_users_email'))

    op.drop_table('auth_users')
    op.drop_table('auth_roles')
    op.drop_table('auth_permissions')
    # ### end Alembic commands ###
