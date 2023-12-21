from apifairy import authenticate, body, response
from flask import Blueprint

from bueno import db
from bueno.auth import token_auth
from bueno.decorators import paginated_response
from bueno.models import Role
from bueno.schemas import RoleSchema

roles = Blueprint("roles", __name__)
role_schema = RoleSchema()
roles_schema = RoleSchema(many=True)


@roles.get("/roles")
@authenticate(token_auth)
@response(roles_schema)
def all():
    """Retrieve all roles"""
    return db.session.scalars(db.select(Role)).all()
