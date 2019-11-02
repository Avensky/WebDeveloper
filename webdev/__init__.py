import os
import json
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_paginate import Pagination, get_page_parameter

app = Flask(__name__)
# engine = create_engine('sqlite:///webdev.db',connect_args={'check_same_thread': False})
# engine = create_engine('postgresql://developer:86developers@localhost:5432/myDatabase')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///webdev.db'

db = SQLAlchemy(app)
#hashing algorythm
bcrypt= Bcrypt(app)

with app.open_resource('client_secrets.json') as f:
	CLIENT_ID = json.load(f)['web']['client_id']
#CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
#	'web']['client_id']
APPLICATION_NAME = "Web Developer"

# login manageR
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


from webdev import routes
