from flask import Flask, url_for, request
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import secrets
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
from flask_qrcode import QRcode
from flask_login import LoginManager, UserMixin, current_user
from flask_admin.theme import Bootstrap4Theme
import logging
from logging.handlers import RotatingFileHandler
from flask_bcrypt import Bcrypt

app = Flask(__name__)

bcrypt = Bcrypt(app)

qrcode = QRcode(app)
login_manager = LoginManager(app)
login_manager.login_view = 'accounts.login'

# Configure the security logger
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)

# File handler to append to security.log
file_handler = RotatingFileHandler("security.log", maxBytes=500000, backupCount=5)
file_handler.setLevel(logging.INFO)

# Create formatter without milliseconds
formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)

# Add the handler to the logger
security_logger.addHandler(file_handler)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = secrets.token_hex(16)

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///csc2031blog.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CAPTCHA CONFIGURATION
app.config['RECAPTCHA_USE_SSL'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = "6LcEQpAqAAAAAJuGiMF9F6Fevk-lG8b4WueXpgc_"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6LcEQpAqAAAAAGyXUM3uPXyKcRDE9ww8wWbUhUwS"

metadata = MetaData(
    naming_convention={
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
    }
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# DATABASE TABLES
class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))
    created = db.Column(db.DateTime, nullable=False)
    title = db.Column(db.Text, nullable=False)
    body = db.Column(db.Text, nullable=False)
    user = db.relationship("User", back_populates="posts")


    def __init__(self, title, body, user):
        self.created = datetime.now()
        self.title = title
        self.body = body
        self.user = user

    def update(self, title, body):
        self.created = datetime.now()
        self.title = title
        self.body = body
        db.session.commit()

class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    log_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user_registration_datetime = db.Column(db.DateTime, nullable=False)
    latest_login_datetime = db.Column(db.DateTime)
    previous_login_datetime = db.Column(db.DateTime)
    latest_ip = db.Column(db.String(45))  # IPv6 compatible
    previous_ip = db.Column(db.String(45))

    user = db.relationship("User", back_populates="log", uselist=False)

    def __init__(self, user_id):
        self.log_user_id = user_id
        self.user_registration_datetime = datetime.now()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)

    #User mfa
    mfa_key = db.Column(db.String(100), nullable=False, default=pyotp.random_base32())
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)

    # User posts
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")

    #User active
    active = db.Column(db.Boolean(), nullable=False, default=True)

    # User role
    role = db.Column(db.String(20), nullable=False, default='end_user')

    # User log
    log = db.relationship("Log", uselist=False, back_populates="user")

    def get_id(self):
        return str(self.id)

    def __init__(self, email, firstname, lastname, phone, password, role):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password
        self.role = role


    def enable_mfa(self):
        """Enable MFA for the user."""
        self.mfa_enabled = True
        db.session.commit()

    @property
    def is_active(self):
        return self.active

    def generate_log(self):
        if not self.log:
            log = Log(user_id=self.id)
            db.session.add(log)
            db.session.commit()

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


# DATABASE ADMINISTRATOR
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')

class PostView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'userid', 'created', 'title', 'body', 'user')


class UserView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'email', 'password', 'firstname', 'lastname', 'phone', 'mfa_key', 'mfa_enabled', 'posts', 'role')

class LogView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'log_user_id', 'user_registration_datetime', 'latest_login_datetime',
                   'previous_login_datetime', 'latest_ip', 'previous_ip')

admin = Admin(app, name='DB Admin', theme=Bootstrap4Theme(fluid=True))
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))
admin.add_view(LogView(Log, db.session))


limiter = Limiter(get_remote_address, app=app)
default_limit = ['500/day']


# IMPORT BLUEPRINTS
from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp

# REGISTER BLUEPRINTS
app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)

