import os
import random 
import string
import json 
import secrets 
import httplib2 
from PIL import Image 
from flask import (Flask, render_template, request, redirect, jsonify, url_for,
			flash, abort, make_response)
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from webdev import app, db, bcrypt, mail
from webdev.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
				PostForm, RequestResetForm, ResetPasswordForm)
from webdev.models import User, Post


################################################################################
################################################################################
# google json
################################################################################
################################################################################
with app.open_resource('client_secrets.json') as f:
	CLIENT_ID = json.load(f)['web']['client_id']
#CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
#	'web']['client_id']
APPLICATION_NAME = "Web Developer"


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
	state = ''.join(random.choice(string.ascii_uppercase + string.digits)for x in range(32))
	login_session['state'] = state
	form = LoginForm()
	if current_user.is_authenticated:
		return redirect(url_for('showHome'))
	if form.validate_on_submit():
#		if form.email.data == 'admin@blog.com' and form.password.data == 'password':
#			flash('You have been logged in!', 'success')
		user = User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password, form.password.data):
			login_user(user)
			next_page = request.args.get('next')
			return redirect(next_page) if next_page else redirect(url_for('showHome', _anchor='welcome'))
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
# logout
################################################################################
################################################################################
#@app.route("/logout")
#@login_required
#def logout():
#    logout_user()
#    return redirect(url_for('showHome'))


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
# facebook connect
################################################################################
################################################################################
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print ("access token received %s ") % access_token
    app_id = json.loads(
	open('/var/www/html/WebDeveloper/fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('/var/www/html/WebDeveloper/fb_client_secrets.json', 'r').read())['web']['app_secret']
#    with app.open_resource('fb_client_secrets.json') as f:
#    app_id = json.load(f)['web']['app_id']
    url = 'https://graph.facebook.com/oauth/access_token?'
    url += 'grant_type=fb_exchange_token&client_id=%s' % app_id
    url += '&client_secret=%s' % app_secret
    url += '&fb_exchange_token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we
        have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace the
        remaining quotes with nothing so that it can be used directly in the
        graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')
    url = 'https://graph.facebook.com/v2.8/me?access_token='
    url += '%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]
    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token
    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token='
    url += '%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]
    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;'
    output += 'border-radius: 150px;-webkit-border-radius: 150px;'
    output += '-moz-border-radius: 150px;"> '
    flash("Now logged in as %s" % login_session['username'])
    return output


################################################################################
################################################################################
# facebook disconnect
################################################################################
################################################################################
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


##############################################################################
##############################################################################
# Google
##############################################################################
##############################################################################
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'
    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output


################################################################################
################################################################################
# User Helper Functions
################################################################################
################################################################################
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    db.session.add(newUser)
    db.session.commit()
    user = User.query.filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = User.query.filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = User.query.filter_by(email=email).one()
        return user.id
    except Exception as e:
        return None

################################################################################
################################################################################
# DISCONNECT - Revoke a current user's token and reset their login_session
################################################################################
################################################################################
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = "make_response(json.dumps('Failed to revoke"
        response += " token for given user.', 400))"
        response.headers['Content-Type'] = 'application/json'
        return response


##############################################################################
##############################################################################
# Disconnect based on provider
##############################################################################
##############################################################################
@app.route('/logout')
def logout():
	if 'provider' in login_session:
		if login_session['provider'] == 'google':
			gdisconnect()
			del login_session['gplus_id']
			del login_session['access_token']
		if login_session['provider'] == 'facebook':
			fbdisconnect()
			del login_session['facebook_id']
		del login_session['email']
		del login_session['picture']
		del login_session['user_id']
		del login_session['provider']
		flash("You have successfully been logged out.")
		return redirect(url_for('showHome'))
	else:
		flash("You were not logged in")
		logout_user()
		return redirect(url_for('showHome'))
