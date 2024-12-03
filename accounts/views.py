import wtforms
from flask import Blueprint, render_template, flash, redirect, url_for, session
from accounts.forms import RegistrationForm, LoginForm
from config import User, db, limiter
import re
from markupsafe import Markup

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')


@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()

    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        if verify_password(form.password.data) == False:
            flash('shit password mate', category="danger")
            return render_template('accounts/registration.html', form=form)
        else:
            new_user = User(email=form.email.data,
                            firstname=form.firstname.data,
                            lastname=form.lastname.data,
                            phone=form.phone.data,
                            password=form.password.data,
                            )

            db.session.add(new_user)
            db.session.commit()

            flash('Account Created', category='success')
            return redirect(url_for('accounts.login'))


    return render_template('accounts/registration.html', form=form)
@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('5/minute')
def login():
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        db.session.query(User).filter_by(password=form.password.data).first()
        if user is not None and (form.password.data == user.password):
            return redirect(url_for('posts.posts'))
        else:
            session['failed_attempts'] += 1
            if session['failed_attempts'] >= 3:
                flash('Login Unsuccessful', category="danger")
                redirect(url_for('accounts.login'))
                flash(Markup('<a href="/unlock">unlock account</a>'))
                return render_template('accounts/login.html')
            else:
                flash(f'Login failed you have {3 - session['failed_attempts']} attempts left', category="danger")
    return render_template('accounts/login.html', form=form)

@accounts_bp.route('/unlock')
def unlock():
    session['failed_attempts'] = 0

    form = LoginForm()
    return render_template('accounts/login.html', form=form)

def verify_password(password):
    passrange = False
    passdigit = False
    passupper = False
    passlower = False
    passspecial = False

    if re.match(r'^.{8,15}$', password):
        passrange = True
    else:
        flash('Password must be between 8 and 15 characters long!')

    if re.search(r'\d', password):
        passdigit = True
    else:
        flash('Password must contain a digit!')

    if re.search(r'[A-Z]', password):
        passupper = True
    else:
        flash('Password must contain at least one uppercase letter!')

    if re.search(r'[a-z]', password):
        passlower = True
    else:
        flash('Password must contain at least one lowercase letter!')

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        passspecial = True
    else:
        flash('Password must contain at least one special character!')

    if not (passrange and passdigit and passupper and passlower and passspecial):
        return False

    return True

@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')