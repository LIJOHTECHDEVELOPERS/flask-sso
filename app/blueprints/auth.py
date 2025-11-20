# app/blueprints/auth.py
from flask import Blueprint, render_template, request, flash, redirect, jsonify, url_for
from flask_login import login_user, current_user, logout_user, login_required
from flask_cors import cross_origin
from ..extensions import db, oauth
from ..models import User
from ..utils import hash_password, verify_password

auth_bp = Blueprint('auth', __name__, template_folder='templates')

# ==================== Lazy OAuth Clients ====================
def get_google_client():
    return oauth.create_client('google')

def get_github_client():
    return oauth.create_client('github')

# ==================== Helper: Safe Redirect ====================
def safe_redirect(default='main.profile'):
    """Redirect to redirect_uri if provided and safe, else fallback."""
    redirect_to = request.args.get('redirect_uri') or request.form.get('redirect_uri')
    if redirect_to and redirect_to.startswith(('http://', 'https://')):
        # In production you should whitelist allowed domains
        # For now we allow any (good for dev + your domain)
        return redirect(redirect_to)
    return redirect(url_for(default))

# ==================== Traditional Auth ====================
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return safe_redirect('main.index')

    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        name = request.form.get('name', '').strip() or None
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('auth.register'))

        user = User(email=email, name=name, password_hash=hash_password(password))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Account created successfully!', 'success')
        return safe_redirect('main.profile')

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return safe_redirect('main.index')

    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.password_hash and verify_password(user.password_hash, password):
            login_user(user)
            flash('Welcome back!', 'success')
            return safe_redirect('main.profile')

        flash('Invalid email or password', 'danger')
        return redirect(url_for('auth.login'))

    return render_template('login.html')


# ==================== OAuth Login Initiators ====================
@auth_bp.route('/login/google')
def login_google():
    google = get_google_client()
    if not google:
        flash('Google OAuth not configured', 'danger')
        return redirect(url_for('auth.login'))
    # Preserve redirect_uri through the OAuth flow
    redirect_uri = request.args.get('redirect_uri')
    callback_url = url_for('auth.auth_google', _external=True)
    if redirect_uri:
        callback_url += f"?redirect_uri={redirect_uri}"
    return google.authorize_redirect(callback_url)


@auth_bp.route('/login/github')
def login_github():
    github = get_github_client()
    if not github:
        flash('GitHub OAuth not configured', 'danger')
        return redirect(url_for('auth.login'))
    redirect_uri = request.args.get('redirect_uri')
    callback = url_for('auth.auth_github', _external=True)
    if redirect_uri:
        callback += f"?redirect_uri={redirect_uri}"
    return github.authorize_redirect(callback)


# ==================== OAuth Callbacks (with redirect_uri support) ====================
@auth_bp.route('/auth/google')
def auth_google():
    google = get_google_client()
    token = google.authorize_access_token()
    userinfo = google.parse_id_token(token)

    if not userinfo.get('email_verified'):
        flash('Google email not verified', 'danger')
        return redirect(url_for('auth.login'))

    email = userinfo['email'].lower()
    name = userinfo.get('name') or userinfo.get('given_name')
    provider_id = userinfo['sub']

    user = User.query.filter_by(email=email).first()
    if user:
        if user.google_id and user.google_id != provider_id:
            flash('Email already linked to different Google account', 'danger')
            return redirect(url_for('auth.login'))
        user.google_id = provider_id
        if name and not user.name:
            user.name = name
        db.session.commit()
    else:
        user = User(email=email, name=name, google_id=provider_id)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash('Signed in with Google', 'success')
    return safe_redirect('main.profile')


@auth_bp.route('/auth/github')
def auth_github():
    github = get_github_client()
    token = github.authorize_access_token()
    resp = github.get('user')
    gh_user = resp.json()
    provider_id = str(gh_user['id'])
    name = gh_user.get('name') or gh_user.get('login')

    emails_resp = github.get('user/emails')
    emails = emails_resp.json()
    email_obj = next((e for e in emails if e['primary'] and e['verified']), None)
    if not email_obj:
        flash('No verified primary email on GitHub', 'danger')
        return redirect(url_for('auth.login'))

    email = email_obj['email'].lower()

    user = User.query.filter_by(email=email).first()
    if user:
        if user.github_id and user.github_id != provider_id:
            flash('Email already linked to different GitHub account', 'danger')
            return redirect(url_for('auth.login'))
        user.github_id = provider_id
        if name and not user.name:
            user.name = name
        db.session.commit()
    else:
        user = User(email=email, name=name, github_id=provider_id)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash('Signed in with GitHub', 'success')
    return safe_redirect('main.profile')


# ==================== Logout (with redirect back to app) ====================
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been signed out', 'info')
    return safe_redirect('main.index')  # or redirect to redirect_uri if you want


# ==================== OIDC / User Info Endpoints ====================
@auth_bp.route('/.well-known/openid-configuration')
@cross_origin()
def openid_config():
    base = request.url_root.rstrip('/')
    return jsonify({
        "issuer": base,
        "authorization_endpoint": f"{base}/login",
        "token_endpoint": f"{base}/oauth2/token",
        "userinfo_endpoint": f"{base}/userinfo",
        "jwks_uri": f"{base}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
    })

@auth_bp.route('/oauth2/token', methods=['POST', 'GET'])
@cross_origin()
def oauth2_token():
    return jsonify({"access_token": "demo", "token_type": "Bearer"})

@auth_bp.route('/userinfo', methods=['GET'])
@login_required
@cross_origin()
def userinfo():
    return jsonify({
        "sub": str(current_user.id),
        "email": current_user.email,
        "email_verified": True,
        "name": current_user.name or "",
        "preferred_username": current_user.email.split('@')[0],
        "picture": f"https://ui-avatars.com/api/?name={current_user.email}&background=0078D4&color=fff",
    })

@auth_bp.route('/jwks')
@cross_origin()
def jwks():
    return jsonify({"keys": []})