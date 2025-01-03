import base64
import secrets
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from datetime import datetime
from markupsafe import Markup
from accounts.forms import RegistrationForm, LoginForm
from config import User, db, limiter, security_logger, bcrypt
import re
import pyotp
from flask_login import login_user, logout_user, current_user




accounts_bp = Blueprint('accounts', __name__, template_folder='templates')


def is_valid_email(email):
    return re.match(r'^[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}$', email)

def is_valid_name(name):
    return re.match(r'^[a-zA-Z-]+$', name)

def is_valid_uk_phone(phone):
    patterns = [
        r'^02\d-\d{8}$',
        r'^011\d-\d{7}$',
        r'^01\d1-\d{7}$',
        r'^01\d{3}-\d{5}$',
        r'^01\d{3}-\d{6}$'
    ]
    return any(re.match(pattern, phone) for pattern in patterns)

@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    if not current_user.is_authenticated:
        form = RegistrationForm()

        if form.validate_on_submit():
            errors = []

            if not is_valid_email(form.email.data):
                errors.append('Invalid email address.')

            if not is_valid_name(form.firstname.data):
                errors.append('First name must only contain letters or hyphens.')

            if not is_valid_name(form.lastname.data):
                errors.append('Last name must only contain letters or hyphens.')

            if not is_valid_uk_phone(form.phone.data):
                errors.append('Invalid UK landline phone number format.')

            if User.query.filter_by(email=form.email.data).first():
                errors.append('Email already exists.')

            if not verify_password(form.password.data):
                errors.append('Invalid password format.')

            if errors:
                for error in errors:
                    flash(error, category="danger")
                return render_template('accounts/registration.html', form=form)

            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            salt = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()[:32]
            new_user = User(email=form.email.data,
                            firstname=form.firstname.data,
                            lastname=form.lastname.data,
                            phone=form.phone.data,
                            password=hashed_password,
                            role='end_user',
                            salt=salt)

            db.session.add(new_user)
            db.session.commit()

            new_user.generate_log()
            security_logger.info(
                f"User registration: Email={new_user.email}, Role={new_user.role}, IP={request.remote_addr}")

            flash('Account Created. Please set up MFA before logging in.', category='success')
            return redirect(url_for('accounts.mfa_setup', mfa_key=new_user.mfa_key))

        return render_template('accounts/registration.html', form=form)
    else:
        flash('Already registered', category="danger")
        return render_template('home/index.html')




@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('5/minute')
def login():
    if not current_user.is_authenticated:
        form = LoginForm()
        if 'failed_attempts' not in session:
            session['failed_attempts'] = 0

        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()

            if not user:
                flash('Invalid credentials. Please try again.', category="danger")
                return render_template('accounts/login.html', form=form)


            if not bcrypt.check_password_hash(user.password, form.password.data):
                session['failed_attempts'] += 1
                remaining_attempts = 3 - session['failed_attempts']

                security_logger.warning(
                    f"Invalid login attempt: Email={form.email.data}, Attempts={session['failed_attempts']}, IP={request.remote_addr}")

                if session['failed_attempts'] >= 3:

                    security_logger.error(
                        f"Maximum invalid login attempts reached: Email={form.email.data}, Attempts={session['failed_attempts']}, IP={request.remote_addr}")

                    flash('Too many failed attempts. Please unlock your account.', category="danger")
                    flash(Markup('<a href="/unlock">unlock account</a>'))

                    return render_template('accounts/login.html')

                flash(f'Incorrect password. {remaining_attempts} attempts left.', category="danger")

                return render_template('accounts/login.html', form=form)


            if not user.mfa_enabled:
                flash('MFA is not set up. Please set it up to continue.', category="warning")

                return redirect(url_for('accounts.mfa_setup', mfa_key=user.mfa_key))


            if not pyotp.TOTP(user.mfa_key).verify(form.mfa_pin.data):
                flash('Invalid MFA code. Please try again.', category="danger")
                security_logger.warning(
                    f"Invalid login attempt: Email={form.email.data}, Attempts={session['failed_attempts']}, IP={request.remote_addr}")
                return render_template('accounts/login.html', form=form)

            if not user.log:
                user.generate_log()

            current_ip = request.remote_addr

            user.log.previous_login_datetime = user.log.latest_login_datetime
            user.log.previous_ip = user.log.latest_ip

            user.log.latest_login_datetime = datetime.now()
            user.log.latest_ip = current_ip
            security_logger.info(f"User login: Email={user.email}, Role={user.role}, IP={request.remote_addr}")
            db.session.commit()


            flash('Login successful!', 'success')
            session.pop('failed_attempts', None)

            login_user(user, remember=False)


            if user.role == 'end_user':
                return render_template('posts/posts.html')

            elif user.role == 'db_admin':
                return redirect('https://127.0.0.1:5000/admin')

            elif user.role == 'sec_admin':
                return render_template('home/index.html')

        return render_template('accounts/login.html', form=form)

    else:
        flash('already logged in', category="danger")
        return render_template('home/index.html')


@accounts_bp.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash('You have been logged out.', 'success')
        return redirect(url_for('accounts.login'))
    else:
        flash('You are not logged in', category="danger")
        return redirect(url_for('accounts.login'))

@accounts_bp.route('/unlock')
def unlock():
    session['failed_attempts'] = 0

    form = LoginForm()
    return render_template('accounts/login.html', form=form)

def verify_password(password):
    pass_range = False
    pass_digit = False
    pass_upper = False
    pass_lower = False
    pass_special = False

    if re.match(r'^.{8,15}$', password):
        pass_range = True
    else:
        flash('Password must be between 8 and 15 characters long!')

    if re.search(r'\d', password):
        pass_digit = True
    else:
        flash('Password must contain a digit!')

    if re.search(r'[A-Z]', password):
        pass_upper = True
    else:
        flash('Password must contain at least one uppercase letter!')

    if re.search(r'[a-z]', password):
        pass_lower = True
    else:
        flash('Password must contain at least one lowercase letter!')

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        pass_special = True
    else:
        flash('Password must contain at least one special character!')

    if not (pass_range and pass_digit and pass_upper and pass_lower and pass_special):
        return False

    return True

@accounts_bp.route('/mfa_setup/<string:mfa_key>', methods=['GET', 'POST'])
def mfa_setup(mfa_key):
    form = LoginForm()
    user = User.query.filter_by(mfa_key=mfa_key).first()

    if not user:
        flash('Invalid MFA setup request. Please try again.', category='danger')
        return redirect(url_for('accounts.login'))

    if request.method == 'POST':
        mfa_pin = request.form.get('mfa_pin')
        totp = pyotp.TOTP(user.mfa_key)
        if totp.verify(mfa_pin):
            user.enable_mfa()
            flash('MFA setup successful! You can now log in using your MFA PIN.', category="success")
            return redirect(url_for('accounts.login'))

        flash('Invalid MFA PIN. Please try again.', category="danger")

    return render_template(
        'accounts/mfa_setup.html',
        form=form,
        user=user,
        uri=str(pyotp.TOTP(user.mfa_key).provisioning_uri(user.email, 'csc 2031 blog'))
    )


@accounts_bp.route('/account')
def account():
    if current_user.is_authenticated:
        return render_template('accounts/account.html')
    else:
        flash('You are not logged in', category="danger")
        return redirect(url_for('accounts.login'))




