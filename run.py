from __init__ import app
##############################################################################
##############################################################################
# start app
##############################################################################
##############################################################################
if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.config['SESSION_TYPE'] = 'filesystem'
	app.debug = True
	app.run(host='0.0.0.0')
