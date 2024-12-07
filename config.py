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
app = Flask(__name__)

qrcode = QRcode(app)
login_manager = LoginManager(app)
login_manager.login_view = 'accounts.login'

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

    def get_id(self):
        return str(self.id)

    def __init__(self, email, firstname, lastname, phone, password):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password


    def enable_mfa(self):
        """Enable MFA for the user."""
        self.mfa_enabled = True
        db.session.commit()

    @property
    def is_active(self):
        return self.active

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    def is_authenticated(self):
        return self.authenticated




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
    column_list = ('id', 'email', 'password', 'firstname', 'lastname', 'phone', 'mfa_key', 'mfa_enabled', 'posts')

admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))


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

