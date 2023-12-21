from apifairy import authenticate, body, response
from apifairy.decorators import other_responses
from flask import Blueprint, abort

from bueno import db
from bueno.auth import token_auth
from bueno.decorators import paginated_response
from bueno.models import User
from bueno.schemas import EmptySchema, UpdateUserSchema, UserSchema

users = Blueprint("users", __name__)
user_schema = UserSchema()
users_schema = UserSchema(many=True)
update_user_schema = UpdateUserSchema(partial=True)


@users.post("/users")
@body(user_schema)
@response(user_schema, 201)
def new(args):
    """Register a new user"""
    for k, v in args.items():
        print(k, v)
    user = User(**args)
    user.create()
    return user


@users.get("/users")
@authenticate(token_auth)
@paginated_response(users_schema)
def all():
    """Retrieve all users"""
    return db.select(User)


@users.get("/users/<int:id>")
@authenticate(token_auth)
@response(user_schema)
@other_responses({404: "User not found"})
def get(id):
    """Retrieve a user by id"""
    return User.read(id) or abort(404)


@users.route("/users/<username>", methods=["GET"])
@authenticate(token_auth)
@response(user_schema)
@other_responses({404: "User not found"})
def get_by_username(username):
    """Retrieve a user by username"""
    return User.read(username) or abort(404)


@users.route("/me", methods=["GET"])
@authenticate(token_auth)
@response(user_schema)
def me():
    """Retrieve the authenticated user"""
    return token_auth.current_user()


@users.route("/me", methods=["PUT"])
@authenticate(token_auth)
@body(update_user_schema)
@response(user_schema)
def put(data):
    """Edit user information"""
    user = token_auth.current_user()
    if "password" in data and (
        "old_password" not in data or not user.verify_password(data["old_password"])
    ):
        abort(400)
    user.update(data)
    db.session.commit()
    return user
