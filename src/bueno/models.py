import secrets
from datetime import datetime, timedelta
from time import time
from typing import Optional

import jwt
import sqlalchemy as sa
from flask import abort, current_app, request, url_for
from sqlalchemy import orm as so
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.orm import backref, relationship, validates
from werkzeug.security import check_password_hash, generate_password_hash

from bueno.app import db
from bueno.database import CRUDMixin


user_role = sa.Table(
    "auth_users_roles",
    db.Model.metadata,
    sa.Column("user_id", sa.ForeignKey("auth_users.id", ondelete="CASCADE")),
    sa.Column("role_id", sa.ForeignKey("auth_roles.id", ondelete="CASCADE")),
)

role_permission = sa.Table(
    "auth_roles_permissions",
    db.Model.metadata,
    sa.Column("role_id", sa.ForeignKey("auth_roles.id", ondelete="CASCADE")),
    sa.Column(
        "permission_id", sa.ForeignKey("auth_permissions.id", ondelete="CASCADE")
    ),
)


class Token(db.Model):
    __tablename__ = "auth_tokens"

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    access_token: so.Mapped[str] = so.mapped_column(sa.String(64), index=True)
    access_expiration: so.Mapped[datetime]
    refresh_token: so.Mapped[str] = so.mapped_column(sa.String(64), index=True)
    refresh_expiration: so.Mapped[datetime]
    user_id: so.Mapped[int] = so.mapped_column(
        sa.ForeignKey("auth_users.id"), index=True
    )

    user: so.Mapped["User"] = so.relationship(back_populates="tokens")

    @property
    def access_token_jwt(self):
        return jwt.encode(
            {"token": self.access_token},
            current_app.config["SECRET_KEY"],
            algorithm="HS256",
        )

    def generate(self):
        self.access_token = secrets.token_urlsafe()
        self.access_expiration = datetime.utcnow() + timedelta(
            minutes=current_app.config["ACCESS_TOKEN_MINUTES"]
        )
        self.refresh_token = secrets.token_urlsafe()
        self.refresh_expiration = datetime.utcnow() + timedelta(
            days=current_app.config["REFRESH_TOKEN_DAYS"]
        )

    def expire(self, delay=None):
        if delay is None:  # pragma: no branch
            # 5 second delay to allow simultaneous requests
            delay = 5 if not current_app.testing else 0
        self.access_expiration = datetime.utcnow() + timedelta(seconds=delay)
        self.refresh_expiration = datetime.utcnow() + timedelta(seconds=delay)

    @staticmethod
    def clean():
        """Remove any tokens that have been expired for more than a day."""
        yesterday = datetime.utcnow() - timedelta(days=1)
        db.session.execute(Token.delete().where(Token.refresh_expiration < yesterday))

    @staticmethod
    def from_jwt(access_token_jwt):
        access_token = None
        try:
            access_token = jwt.decode(
                access_token_jwt, current_app.config["SECRET_KEY"], algorithms=["HS256"]
            )["token"]
            return db.session.scalar(
                Token.select().filter_by(access_token=access_token)
            )
        except jwt.PyJWTError:
            pass


class User(CRUDMixin, db.Model):
    __tablename__ = "auth_users"

    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True, unique=True)
    # name: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))

    last_seen: so.Mapped[datetime]
    active: so.Mapped[bool] = so.mapped_column(sa.Boolean, nullable=False, default=True)
    confirmed: so.Mapped[bool] = so.mapped_column(sa.Boolean, default=False)
    force_pwd_change: so.Mapped[bool] = so.mapped_column(
        sa.Boolean, nullable=False, default=False
    )
    failed_logins: so.Mapped[int] = so.mapped_column(
        sa.Integer, nullable=False, default=0
    )

    tokens: so.WriteOnlyMapped["Token"] = so.relationship(back_populates="user")

    _roles = relationship(
        "Role",
        secondary=user_role,
        backref=backref("users", lazy="dynamic"),
    )
    roles = association_proxy("_roles", "name")

    type: so.Mapped[str] = so.mapped_column(sa.String(20))

    __mapper_args__ = {
        "polymorphic_on": type,
        "polymorphic_identity": "user",
    }

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    @property
    def permissions(self) -> list:
        """Returns a list of __distinct__ permissions"""
        result = list()
        for role in self._roles:
            for permission in role.permissions:
                result.append(permission.name)

        return list(set(result))

    def has_permission(self, permission=None):
        if not permission:
            permission = request.endpoint

        return self.is_admin or permission in self.permissions

    def ping(self):
        # self.last_seen = datetime.utcnow()
        pass

    @classmethod
    def read(cls, id) -> object or None:
        if any(
            (
                isinstance(id, (str, bytes)) and id.isdigit(),
                isinstance(id, (int, float)),
            )
        ):
            return db.session.get(cls, int(id)) or abort(404)

        if isinstance(id, (str, bytes)) and not id.isdigit():
            if "@" in id:
                query = db.select(cls).where(cls.email == id)

            else:
                query = db.select(cls).where(cls.username == id)

            return db.session.scalar(query) or abort(404)
        return None

    @validates("active")
    def validate_active(self, key, value):
        """Validate active status

        Check if the current user tries to deactivate his/her own accout
        and abort if so. Othervise retur the value unmodified."""

        from bueno.auth import token_auth

        if token_auth.current_user == self and value is False:
            abort(403, "You cannot deactivate our own account.")
        return value

    def generate_auth_token(self):
        token = Token(user=self)
        token.generate()
        return token

    @staticmethod
    def verify_access_token(access_token_jwt, refresh_token=None):
        token = Token.from_jwt(access_token_jwt)
        if token:
            if token.access_expiration > datetime.utcnow():
                token.user.ping()
                db.session.commit()
                return token.user

    @staticmethod
    def verify_refresh_token(refresh_token, access_token_jwt):
        token = Token.from_jwt(access_token_jwt)
        if token and token.refresh_token == refresh_token:
            if token.refresh_expiration > datetime.utcnow():
                return token

            # someone tried to refresh with an expired token
            # revoke all tokens from this user as a precaution
            token.user.revoke_all()
            db.session.commit()

    def revoke_all(self):
        db.session.execute(Token.delete().where(Token.user == self))

    def generate_reset_token(self):
        return jwt.encode(
            {
                "exp": time() + current_app.config["RESET_TOKEN_MINUTES"] * 60,
                "reset_email": self.email,
            },
            current_app.config["SECRET_KEY"],
            algorithm="HS256",
        )

    @staticmethod
    def verify_reset_token(reset_token):
        try:
            data = jwt.decode(
                reset_token, current_app.config["SECRET_KEY"], algorithms=["HS256"]
            )
        except jwt.PyJWTError:
            return
        return db.session.scalar(User.select().filter_by(email=data["reset_email"]))

    # Define short aliases for the functions with long names
    hp = has_permission


class Role(CRUDMixin, db.Model):
    __tablename__ = "auth_roles"
    name: so.Mapped[str] = so.mapped_column(sa.String(128))
    description: so.Mapped[str] = so.mapped_column(sa.String(128))
    group: so.Mapped[str] = so.mapped_column(sa.String(128))
    permissions: so.Mapped[str] = relationship(
        "Permission",
        secondary=role_permission,
        backref="roles",
    )
    _users = association_proxy("users", "username")
    _permissions = association_proxy("permissions", "name")

    def __str__(self):
        return f"{self.name}"

    def __repr__(self):
        return f"<Role: {self.name}>"

    @validates("name")
    def validate_name(self, key, value):
        return value.lower()

    @validates("group")
    def validate_group(self, key, value):
        return value.capitalize()

    def update_users(self, selected_users=[]):
        users = db.session.scalars(User.select())

        for user in users:
            if user.username in selected_users and user not in self.users:
                self.users.append(user)
            if user.username not in selected_users and user in self.users:
                self.users.remove(user)

    def update_permissions(self, selected_permissions=[]):
        query = Permission.select()
        permissions = db.session.scalars(query)

        for permission in permissions:
            if (
                permission.name in selected_permissions
                and permission not in self.permissions
            ):
                self.permissions.append(permission)
            if (
                permission.name not in selected_permissions
                and permission in self.permissions
            ):
                self.permissions.remove(permission)

    @staticmethod
    def on_changed_name(target, value, oldvalue, initiator):
        target.group = value.split("-")[0]


class Permission(CRUDMixin, db.Model):
    __tablename__ = "auth_permissions"
    name = so.mapped_column(sa.String(128), unique=True)
    group = so.mapped_column(sa.String(128))
    parent = so.mapped_column(sa.String(128), default=None)

    def __str__(self):
        return f"{self.name}"

    def __repr__(self):
        return f"<Permission: {self.name}>"

    @staticmethod
    def on_changed_name(target, value, oldvalue, initiator):
        target.group = value.split(".")[0]
