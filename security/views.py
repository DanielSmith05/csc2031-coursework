from flask import Blueprint, render_template, flash
from flask_login import current_user
from config import User

security_bp = Blueprint('security', __name__, template_folder='templates')

@security_bp.route('/security')
def security():
    if current_user.role == 'sec_admin':
        users = User.query.all()
        with open("security.log", "r") as f:
            logs = f.readlines()[-10:]
            logs = logs[::-1]
        return render_template('security/security.html', users=users, logs=logs)
    else:
        flash('You are not authorized to access this page.')
        return render_template('home/index.html')