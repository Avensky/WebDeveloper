import os
import json
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key'
# engine = create_engine('postgresql://developer:86developers@localhost:5432/myDatabase')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///webdev.db'
db = SQLAlchemy(app)
# hashing algorythm
bcrypt= Bcrypt(app)
# login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
# Session
app.config['SESSION_TYPE'] = 'filesystem'
# EMAIL SETTINGS
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')

mail = Mail(app)

from webdev import routes