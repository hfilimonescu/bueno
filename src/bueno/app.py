from apifairy import APIFairy
from flask import Flask, redirect, url_for
from flask_cors import CORS
from flask_mail import Mail
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from bueno.config import Config


apifairy = APIFairy()
cors = CORS()
db = SQLAlchemy()
ma = Marshmallow()
mail = Mail()
migrate = Migrate()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    from bueno.errors import errors
    from bueno.roles import roles
    from bueno.users import users

    db.init_app(app)
    ma.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    apifairy.init_app(app)
    if app.config.get("USE_CORS", "True"):
        cors.init_app(app)

    app.register_blueprint(errors)
    app.register_blueprint(roles, url_prefix="/api")
    app.register_blueprint(users, url_prefix="/api")

    @app.get("/")
    def index():
        return redirect(url_for("apifairy.docs"))

    return app
