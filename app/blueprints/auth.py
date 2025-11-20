# app/blueprints/auth.py
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, current_user, logout_user, login_required
from ..extensions import db, oauth
from ..models import User
from ..utils import hash_password, verify_password

auth_bp = Blueprint('auth', __name__, template_folder='templates')

# ==================== Lazy OAuth Clients ====================
def get_google_client():
    return oauth.create_client('google')

def get_github_client():
    return oauth.create_client('github')

# ==================== Traditional Auth ====================
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

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
        return redirect(url_for('main.profile'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.password_hash and verify_password(user.password_hash, password):
            login_user(user)
            flash('Welcome back!', 'success')
            return redirect(url_for('main.profile'))

        flash('Invalid email or password', 'danger')

    return render_template('login.html')


# ==================== OAuth Login Routes ====================
@auth_bp.route('/login/google')
def login_google():
    google = get_google_client()
    if not google:
        flash('Google OAuth not configured', 'danger')
        return redirect(url_for('auth.login'))
    redirect_uri = url_for('auth.auth_google', _external=True)
    return google.authorize_redirect(redirect_uri)


@auth_bp.route('/login/github')
def login_github():
    github = get_github_client()
    if not github:
        flash('GitHub OAuth not configured', 'danger')
        return redirect(url_for('auth.login'))
    redirect_uri = url_for('auth.auth_github', _external=True)
    return github.authorize_redirect(redirect_uri)


# ==================== OAuth Callbacks (Hybrid Logic) ====================
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
            flash('This email is already linked to a different Google account', 'danger')
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
    return redirect(url_for('main.profile'))


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
        flash('No verified primary email found on GitHub', 'danger')
        return redirect(url_for('auth.login'))

    email = email_obj['email'].lower()

    user = User.query.filter_by(email=email).first()
    if user:
        if user.github_id and user.github_id != provider_id:
            flash('This email is already linked to a different GitHub account', 'danger')
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
    return redirect(url_for('main.profile'))


# ==================== Logout ====================
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been signed out', 'info')
    return redirect(url_for('main.index'))

@auth_bp.route('/.well-known/openid-configuration')
def openid_config():
    request_base_url = request.url_root
    return jsonify({
        "issuer": request_base_url,
        "authorization_endpoint": url_for('auth.login', _external=True),
        "token_endpoint": url_for('auth.oauth2_token', _external=True),  # we'll add
        "userinfo_endpoint": url_for('auth.userinfo', _external=True),
        "jwks_uri": url_for('auth.jwks', _external=True),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
    })

@auth_bp.route('/oauth2/token')
def oauth2_token():
    # Simplified — real apps use proper OAuth2 flow
    # But this works for most libraries in "Resource Owner Password" or testing
    return jsonify({"access_token": "demo", "token_type": "Bearer"})

@auth_bp.route('/userinfo')
@login_required
def userinfo():
    return jsonify({
        "sub": str(current_user.id),
        "email": current_user.email,
        "email_verified": True,
        "name": current_user.name,
        "preferred_username": current_user.email.split('@')[0],
    })

@auth_bp.route('/jwks')
def jwks():
    return jsonify({"keys": []})