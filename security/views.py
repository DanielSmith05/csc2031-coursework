from flask import Blueprint, render_template, url_for, redirect, flash, request
from flask_login import current_user
from config import User

security_bp = Blueprint('security', __name__, template_folder='templates')

@security_bp.route('/security')
def security():
    if current_user.role == 'sec_admin':
        users = User.query.all()
        return render_template('security/security.html', users=users)
    else:
        flash('You must be logged in to view this page.')
        return redirect(url_for('accounts.logout'))