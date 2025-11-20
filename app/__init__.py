# app/__init__.py
from flask import Flask
from flask_cors import CORS
from .extensions import db, login_manager, oauth, migrate
from .models import User
from .blueprints import register_blueprints
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # ⭐ FIX 1: Configure Session Cookie for Cross-Origin (SameSite=None; Secure)
    # This is required for the client-side fetch() with credentials
    # from your frontend domain (cross-origin) to work reliably.
    # NOTE: This REQUIRES the Flask app to run under HTTPS in production.
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'
    app.config['SESSION_COOKIE_SECURE'] = True
    
    # ⭐ FIX 2: Gracefully handle the FRONTEND_URL environment variable 
    # to prevent 'TypeError: argument of type 'NoneType' is not iterable'
    allowed_origins = [
        "http://localhost:8080",
        "http://localhost:5000",
        "http://localhost:3000",
        "https://auth.digikenya.co.ke"
        # Add your production frontend domain (e.g., "https://app.digikenya.co.ke")
    ]
    
    # Check if the environment variable is set before appending
    frontend_url = os.getenv('FRONTEND_URL')
    if frontend_url:
        allowed_origins.append(frontend_url)

    # Initialize CORS - MUST be done early before routes are registered
    CORS(app, resources={
        r"/*": {
            "origins": allowed_origins, # Use the safe list of origins
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
            "supports_credentials": True,
            "expose_headers": ["Content-Type", "Authorization"]
        }
    })

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

    # Register blueprints AFTER CORS is initialized
    register_blueprints(app)

    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()

    return app