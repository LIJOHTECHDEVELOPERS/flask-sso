# app/blueprints/main.py
from flask import Blueprint, render_template, url_for
from flask_login import login_required, current_user

main_bp = Blueprint('main', __name__, template_folder='templates')

@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('profile.html')  # We'll create this next
    return render_template('home.html')

@main_bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html')