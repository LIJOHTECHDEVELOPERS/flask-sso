# app/__init__.py
from flask import Flask, request # <-- ADDED 'request' import
from flask_cors import CORS
from .extensions import db, login_manager, oauth, migrate
from .models import User
from .blueprints import register_blueprints
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # FIX 1: Configure Session Cookie for Cross-Origin (SameSite=None; Secure)
    # This is required for the browser to send cookies in cross-site fetch calls.
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'
    app.config['SESSION_COOKIE_SECURE'] = True
    
    # FIX 2: Gracefully handle the FRONTEND_URL environment variable
    allowed_origins = [
        "http://localhost:8080",
        "http://localhost:5000",
        "http://localhost:3000",
        "https://auth.digikenya.co.ke"
        # Add your production frontend domain here when deployed
    ]
    
    frontend_url = os.getenv('FRONTEND_URL')
    if frontend_url:
        allowed_origins.append(frontend_url)

    # Initialize CORS
    CORS(app, resources={
        r"/*": {
            "origins": allowed_origins,
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
            "supports_credentials": True, # This tells flask-cors to try setting the header
            "expose_headers": ["Content-Type", "Authorization"]
        }
    })

    # FIX 3: Explicitly set CORS headers via @after_request
    # This ensures the critical 'Access-Control-Allow-Credentials: true'
    # header is present even if flask-cors or an upstream proxy fails to set it,
    # resolving the console error.
    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get('Origin')
        
        # Only set headers if the request is from an allowed origin
        if origin and origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
            # Crucial fix for "credentials mode is 'include'" error:
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        
        # Handle OPTIONS preflight requests if needed (though flask-cors usually handles this)
        if request.method == 'OPTIONS':
            response.status_code = 200
        
        return response

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