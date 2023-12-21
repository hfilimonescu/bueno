from marshmallow import ValidationError, validate, validates, validates_schema

from bueno import db, ma
from bueno.auth import token_auth
from bueno.models import Role, User, Permission

paginated_schema_cache = {}


class EmptySchema(ma.Schema):
    pass


class StringPaginationSchema(ma.Schema):
    class Meta:
        ordered = True

    limit = ma.Integer()
    offset = ma.Integer()
    after = ma.String(load_only=True)
    count = ma.Integer(dump_only=True)
    total = ma.Integer(dump_only=True)

    @validates_schema
    def validate_schema(self, data, **kwargs):
        if data.get("offset") is not None and data.get("after") is not None:
            raise ValidationError("Cannot specify both offset and after")


def PaginatedCollection(schema, pagination_schema=StringPaginationSchema):
    if schema in paginated_schema_cache:
        return paginated_schema_cache[schema]

    class PaginatedSchema(ma.Schema):
        class Meta:
            ordered = True

        pagination = ma.Nested(pagination_schema)
        data = ma.Nested(schema, many=True)

    PaginatedSchema.__name__ = "Paginated{}".format(schema.__class__.__name__)
    paginated_schema_cache[schema] = PaginatedSchema
    return PaginatedSchema


class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User
        ordered = True

    id = ma.auto_field(dump_only=True)
    username = ma.auto_field(required=True, validate=validate.Length(min=3, max=64))
    email = ma.auto_field(
        required=True, validate=[validate.Length(max=120), validate.Email()]
    )
    password = ma.String(required=True, load_only=True, validate=validate.Length(min=8))
    roles = ma.String()
    permissions = ma.String()
    has_password = ma.Boolean(dump_only=True)
    last_seen = ma.auto_field(dump_only=True)

    @validates("username")
    def validate_username(self, value):
        if not value[0].isalpha():
            raise ValidationError("Username must start with a letter")
        user = token_auth.current_user()
        old_username = user.username if user else None
        if value != old_username and db.session.scalar(
            db.select(User).filter_by(username=value)
        ):
            raise ValidationError("Use a different username.")

    @validates("email")
    def validate_email(self, value):
        user = token_auth.current_user()
        old_email = user.email if user else None
        if value != old_email and db.session.scalar(
            db.select(User).filter_by(email=value)
        ):
            raise ValidationError("Use a different email.")


class UpdateUserSchema(UserSchema):
    old_password = ma.String(load_only=True, validate=validate.Length(min=3))

    @validates("old_password")
    def validate_old_password(self, value):
        if not token_auth.current_user().verify_password(value):
            raise ValidationError("Password is incorrect")


class PermissionSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Permission
        ordered = True

    # id = ma.auto_field(dump_only=True)
    # group = ma.auto_field(dump_only=True)
    # name = ma.auto_field(required=True, validate=validate.Length(min=3, max=64))
    # roles = ma.Nested(RoleSchema, dump_only=True)


class RoleSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Role
        ordered = True

    # id = ma.auto_field(dump_only=True)
    # group = ma.auto_field(dump_only=True)
    # name = ma.auto_field(required=True, validate=validate.Length(min=3, max=64))
    # permissions = ma.Nested(PermissionSchema, dump_only=True)
