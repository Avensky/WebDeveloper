import os, random, string, json, secrets, httplib2, flask, requests
from PIL import Image
from flask import (Flask, render_template, request, redirect, jsonify, url_for,
					flash, abort, make_response)
from flask import session as login_session
from flask_mail import Message
from flask_login import login_user, current_user, logout_user, login_required
from webdev import app, db, bcrypt, mail, login_manager
from webdev.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
							PostForm, RequestResetForm, ResetPasswordForm)
from webdev.models import User, Post
from oauthlib.oauth2 import WebApplicationClient


################################################################################
################################################################################
# handlers
################################################################################
################################################################################
@login_manager.unauthorized_handler
def unauthorized():
	return "You must be logged in to access this content.", 403

################################################################################
################################################################################
# home
################################################################################
################################################################################
@app.route('/')
@app.route('/home')
def showHome():
	return render_template('home.html')


################################################################################
################################################################################
# blog
################################################################################
################################################################################
@app.route('/blog')
def showBlog():
	page = request.args.get('page', type=int, default=1)
	posts = Post.query.order_by(Post.id.desc()).paginate(page=page, per_page=5)
	return render_template('blog.html', posts=posts)


################################################################################
################################################################################
# posts by user
################################################################################
################################################################################
@app.route("/user/<string:username>")
def user_posts(username):
	page = request.args.get('page', type=int, default=1)
	user = User.query.filter_by(username=username).first_or_404()
	posts = Post.query.filter_by(author=user).order_by(Post.id.desc()).paginate(page=page, per_page=5)
	image_file = url_for('static',filename='pics/' + user.image_file)
	return render_template('user_posts.html', posts=posts, user=user, image_file = image_file)

################################################################################
################################################################################
# register
################################################################################
################################################################################
@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegistrationForm()
	if  form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(user)
		db.session.commit()
		flash(f'Account created for {form.username.data}!', 'success')
		return redirect(url_for('login'))
	return render_template('register.html', title='Register', form=form)


################################################################################
################################################################################
# login
################################################################################
################################################################################
@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if current_user.is_authenticated:
		return redirect(url_for('showHome'))
	if form.validate_on_submit():
#		if form.email.data == 'admin@blog.com' and form.password.data == 'password':
#			flash('You have been logged in!', 'success')
		user = User.query.filter_by(email=form.email.data).first()
		password = User.query.filter_by(password=form.password.data).first()
		if password:
			if user and bcrypt.check_password_hash(user.password, form.password.data):
				login_user(user)
				next_page = request.args.get('next')
				return redirect(next_page) if next_page else redirect(url_for('showHome', _anchor='welcome'))
			else:
				flash('Login Unsuccessful. Please check username and password', 'danger')
		else:
			flash('Login Unsuccessful. Please check username and password', 'danger')

# return "The current session state is %s" % login_session['state']
	return render_template('login.html', title='Login', form=form)


################################################################################
################################################################################
# picture
################################################################################
################################################################################
def save_picture(form_picture):
	random_hex = secrets.token_hex(8)
	f_name, f_ext = os.path.splitext(form_picture.filename)
	picture_fn = random_hex + f_ext
	picture_path = os.path.join(app.root_path, 'static/pics', picture_fn)
	form_picture.save(picture_path)
	output_size = (125, 125)
	i = Image.open(form_picture)
	i.thumbnail(output_size)
	i.save(picture_path)
	return picture_fn


################################################################################
################################################################################
# account
################################################################################
################################################################################
@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
	form = UpdateAccountForm()
	if form.validate_on_submit():
		if form.picture.data:
			picture_file= save_picture(form.picture.data)
			current_user.image_file = picture_file
		current_user.username = form.username.data
		current_user.email = form.email.data
		db.session.commit()
		flash('your account has been updated', 'success')
		return redirect(url_for('account'))
	elif request.method == 'GET':
		form.username.data = current_user.username
		form.email.data = current_user.email
	image_file = url_for('static', filename='pics/' + current_user.image_file)
	return render_template('account.html', title='account',
							image_file=image_file, form=form)


################################################################################
################################################################################
# new posts
################################################################################
################################################################################
@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
	form = PostForm()
	if form.validate_on_submit():
		post = Post(title=form.title.data, content=form.content.data, author=current_user)
		db.session.add(post)
		db.session.commit()
		flash('Your post has been created!', 'success')
		return redirect(url_for('showBlog'))
	return render_template('create_post.html', title='New Post',
							form=form, legend='New Post')


################################################################################
################################################################################
# post_id
################################################################################
################################################################################
@app.route("/post/<int:post_id>", methods=['GET'])
def post(post_id):
	post = Post.query.get(post_id)
	user = User.query.get(post.user_id)
	image_file = url_for('static',filename='pics/' + user.image_file)
	return render_template('post.html', title=post.title, post=post, user=user, image_file = image_file)


################################################################################
################################################################################
# post_id update
################################################################################
################################################################################
@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
	post = Post.query.get(post_id)
	if post.author != current_user:
		abort(403)
	form = PostForm()
	if form.validate_on_submit():
		post.title = form.title.data
		post.content = form.content.data
		db.session.commit()
		flash('Your post has been updated', 'success')
		return redirect(url_for('post', post_id=post.id))
	elif request.method == 'GET':
		form.title.data = post.title
		form.content.data = post.content
	return render_template('create_post.html', title='Update Post',
							form=form, legend='Update Post')


################################################################################
################################################################################
# post_id delete
################################################################################
################################################################################
@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
	post = Post.query.get(post_id)
	if post.author != current_user:
		abort(403)
	db.session.delete(post)
	db.session.commit()
	flash('Your post has been deleted', 'success')
	return redirect(url_for('showHome', _anchor='blog'))


################################################################################
################################################################################
# send reset email
################################################################################
################################################################################
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
					sender='urielzacarias@gmail.com',
					recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request please ignore this message.
'''
    mail.send(msg)


################################################################################
################################################################################
# reset request
################################################################################
################################################################################
@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
	if current_user.is_authenticated:
		return redirect(url_for('showHome'))
	form = RequestResetForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		send_reset_email(user)
		flash('An email has been sent with instructions to reset your password.', 'info')
		return redirect(url_for('login'))
	return render_template('reset_request.html', title='Reset Password', form=form)


################################################################################
################################################################################
# Reset token
################################################################################
################################################################################
@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
	if current_user.is_authenticated:
		return redirect(url_for('showHome'))
	user = User.verify_reset_token(token)
	if user is None:
		flash('That is an invalid or expired token', 'warning')
		return redirect(url_for('reset_request'))
	form = ResetPasswordForm()
	if  form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user.password = hashed_password
		db.session.commit()
		flash(f'Your password has been updated!', 'success')
		return redirect(url_for('login'))
	return render_template('reset_token.html', title='Reset Password', form=form)


################################################################################
################################################################################
# Facebook info
################################################################################
################################################################################


################################################################################
################################################################################
# Facebook login
################################################################################
################################################################################
@app.route("/fbconnect", methods=['POST'])
def fbconnect():
	access_token = request.data
	access_token = access_token.decode('utf-8')
	print ("access token received %s " % access_token)

	with app.open_resource('fb_client_secrets.json') as f:
		app_id = json.load(f)['web']['app_id']
	with app.open_resource('fb_client_secrets.json') as f:
		app_secret = json.load(f)['web']['app_secret']

	url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
		app_id, app_secret, access_token)
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	result = result.decode('utf-8')
	print ("url sent for token access:%s"% url)
	print ("token JSON result: %s" % result)

	# Use token to get user info from API
	userinfo_url = "https://graph.facebook.com/v5.0/me"
	'''
	    Due to the formatting for the result from the server token exchange we
	    have to split the token first on commas and select the first index
	    which gives us the key : value for the server access token then we
	    split it on colons to pull out the actual token value and replace the
	    remaining quotes with nothing so that it can be used directly in the
	    graph api calls
	'''
	token = result
	print ("the token is:%s"% token)
	token = token.split(',')[0].split(':')[1].replace('"', '')

	url = 'https://graph.facebook.com/v5.0/me?access_token=%s&fields=name,id,email' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	print ("url sent for API access:%s"% url)
	print ("API JSON result: %s" % result)
	data = json.loads(result)
	unique_id = data['id']
	users_name = data['name']
	users_email = data["email"]

	# Get user picture
	url = 'https://graph.facebook.com/v5.0/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	data = json.loads(result)

	picture = data["data"]["url"]

	# Create a user in our db with the information provided by Google
	#user = User(id=unique_id, username=users_name, email=users_email, image_file=picture)
	# see if user exists, if it doesn't make a new one
	user = User(
    	social_id=unique_id, username=users_name, email=users_email, image_file=picture)

	if not User.query.filter_by(email=users_email).first():
		newUser = User(
	        social_id=unique_id, username=users_name, email=users_email, image_file=picture)
		db.session.add(user)
		db.session.commit()

	user = User.query.filter_by(email=users_email).first()
	login_user(user)
	flash(f'you are now logged in!', 'success')
	return redirect(url_for('showBlofg'))


################################################################################
################################################################################
# google info
################################################################################
################################################################################
with app.open_resource('client_secrets.json') as f:
	CLIENT_ID = json.load(f)['web']['client_id']
with app.open_resource('client_secrets.json') as f:
	CLIENT_SECRET = json.load(f)['web']['client_secret']
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration")

# OAuth2 client setup
client = WebApplicationClient(CLIENT_ID)

@app.route("/gconnect")
def gconnect():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],)
    return redirect(request_uri)


################################################################################
################################################################################
# Google signin
################################################################################
################################################################################
@app.route("/gconnect/callback")
def callback():
	# Get authorization code Google sent back to you
	code = request.args.get("code")

	# Find out what URL to hit to get tokens that allow you to ask for
	# things on behalf of a user
	google_provider_cfg = get_google_provider_cfg()
	token_endpoint = google_provider_cfg["token_endpoint"]

	# Prepare and send request to get tokens! Yay tokens!
	token_url, headers, body = client.prepare_token_request(
		token_endpoint,
		authorization_response=request.url,
		redirect_url=request.base_url,
		code=code,
	)
	token_response = requests.post(
		token_url,
		headers=headers,
		data=body,
		auth=(CLIENT_ID, CLIENT_SECRET),
	)

	# Parse the tokens!
	client.parse_request_body_response(json.dumps(token_response.json()))

	# Now that we have tokens (yay) let's find and hit URL
	# from Google that gives you user's profile information,
	# including their Google Profile Image and Email
	userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
	uri, headers, body = client.add_token(userinfo_endpoint)
	userinfo_response = requests.get(uri, headers=headers, data=body)

	# We want to make sure their email is verified.
	# The user authenticated with Google, authorized our
	# app, and now we've verified their email through Google!
	if userinfo_response.json().get("email_verified"):
		unique_id = userinfo_response.json()["sub"]
		users_email = userinfo_response.json()["email"]
		picture = userinfo_response.json()["picture"]
		users_name = userinfo_response.json()["given_name"]
	else:
	    return "User email not available or not verified by Google.", 400

	# Create a user in our db with the information provided by Google
	#user = User(id=unique_id, username=users_name, email=users_email, image_file=picture)
	# see if user exists, if it doesn't make a new one
	user = User(
    	social_id=unique_id, username=users_name, email=users_email, image_file=picture)

	if not User.query.filter_by(email=users_email).first():
		newUser = User(
	        social_id=unique_id, username=users_name, email=users_email, image_file=picture)
		db.session.add(user)
		db.session.commit()

	user = User.query.filter_by(email=users_email).first()
	login_user(user)
	flash(f'you are now logged in!', 'success')
	return redirect(url_for('showBlog'))

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


################################################################################
################################################################################
# User Helper Functions
################################################################################
################################################################################
def getUserInfo(unique_id):
    user = User.query.filter_by(id=unique_id).one()
    return user


def getUserID(email):
    try:
        user = User.query.filter_by(email=email).one()
        return user.id
    except Exception as e:
        return None


##############################################################################
##############################################################################
# Disconnect based on provider
##############################################################################
##############################################################################
@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash(f'you are now logged out!', 'success')
	return redirect(url_for('login'))
