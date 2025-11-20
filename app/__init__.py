# app/__init__.py
from flask import Flask
from .extensions import db, login_manager, oauth, migrate
from .models import User
from .blueprints import register_blueprints
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    oauth.init_app(app)

    # Register OAuth clients ONLY if credentials exist (safe for db init & first run)
    google_id = app.config.get('GOOGLE_CLIENT_ID')
    google_secret = app.config.get('GOOGLE_CLIENT_SECRET')
    if google_id and google_secret:
        oauth.register(
            name='google',
            client_id=google_id,
            client_secret=google_secret,
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={'scope': 'openid email profile'}
        )

    github_id = app.config.get('GITHUB_CLIENT_ID')
    github_secret = app.config.get('GITHUB_CLIENT_SECRET')
    if github_id and github_secret:
        oauth.register(
            name='github',
            client_id=github_id,
            client_secret=github_secret,
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize',
            api_base_url='https://api.github.com/',
            client_kwargs={'scope': 'user:email'}
        )

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    register_blueprints(app)

    return app