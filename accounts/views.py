from flask import Blueprint, render_template, flash, redirect, url_for
from accounts.forms import RegistrationForm
from config import User, db

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')


@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()

    if form.validate_on_submit():
        flash('Account Created', category='success')
        return redirect(url_for('accounts.login'))

    return render_template('accounts/registration.html', form=form)

@accounts_bp.route('/login')
def login():
    return render_template('accounts/login.html')


@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')