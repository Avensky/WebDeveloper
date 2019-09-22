# Linux Server & Item Catalog Web App Template

## Important Details
Domain: https://www.urielzacarias.com
Server address: 54.200.79.28
ssh port 2200

Test user login facebook  
Email: 
Password:  

## Description
* This project uses queries to create, read, update, and delete from a database.
* It implements login and user authentication.
* It uses a combination programs configured on a Linux server
* Final version available at https://www.urielzacarias.com

## Project Goals
This project will create a database in which users can create, read, update,
and delete from a catalog of
vegan restaurants. For simplicity it only supports one state at this time.

## Programs and Technologies used
* Ubuntu 18.04.1 LTS
* Python 3
* python 2
* PostgreSQL
* Flask
* Apache2
* Mod-wsgi
* certbot
* oauth2client
* requests
* httplib2
* postgresql
* python-psycopg2
* python-sqlalchemy

## Configurations made to server on server providers site
* Created a static ip
* Changed to custom ssh port
* Added port to allow https

## Security and server changes
* Updated all packages
* Enforced key authentication
* Set up Firewall to allow http, https, ssh, ntp
* Disabled Root Login
* Changed time zone
* Changed connection port
* Created postgreSQL database and user
* Configured apache to serve flask app using mod-wsgi
* Installed certbot to secure connetion/enable HTTPS

## Domain
* routed domain name to server

## Resources used to complete project  
https://www.youtube.com/watch?v=goToXTC96Co&t=183s  
https://www.youtube.com/watch?v=LUFn-QVcmB8  
https://www.youtube.com/watch?v=Gdys9qPjuKs  
https://certbot.eff.org/  
https://tecadmin.net/install-apache-mod-wsgi-on-ubuntu-16-04-xenial/  
https://www.digitalocean.com/community/tutorials/how-to-set-up-apache-virtual-hosts-on-ubuntu-14-04-lts





# Linux virtual machine serving flask app with mod wsgi

## Set up Amazon Lightsail instance
* Select Linux/Unix Ubuntu 18 LTS
* Go to Networking tab and addn 
**	custom   tcp   2200
**	custom   tcp   5000
**	custom   udp   123

## Connect via ssh
* Update Current packages
* sudo apt update
* sudo apt upgrade
** accept changes but also keep local versions currently installed
* sudo apt autoremove

## Set up Firewall
* sudo ufw default deny incoming
* sudo ufw default allow outgoing
* sudo ufw allow ssh
* sudo ufw allow 2200/tcp
* sudo ufw allow www
* sudo ufw allow https
* sudo ufw allow ntp
* sudo ufw enable

## create user
* sudo adduser poly
** pw: 86cats!
* sudo cp /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/poly
* sudo nano /etc/sudoers.d/poly
**	grader ALL=(ALL) NOPASSWD:ALL
* sudo nano /etc/ssh/sshd_config
** Permit Root Login yes
** Password Authentication yes
* sudo reboot
* sudo service sshd restart

## In local environment
* ssh-keygen
* c/users/uriel/.ssh/id_rsa: 

## ssh to server
* ssh poly@54.200.79.28 
* mkdir .ssh
* touch .ssh/authorized_keys
* nano .ssh/authorized_keys
** ssh-rsa AAAA...
* chmod 700 .ssh
* chmod 644 .ssh/authorized_keys

* sudo nano /etc/ssh/sshd_config
** port 2200
** Password Authentication no
* sudo service ssh restart	
* ssh poly@54.200.79.28  -p 2200
* sudo nano /etc/ssh/sshd_config
** PermitRootLogin no
* sudo service ssh restart
* sudo reboot
* ssh poly@54.200.79.28 -p 2200

## Check status to remove old ports
* sudo ufw status
* sudo ufw delete #
* sudo timedatectl set-timezone UTC

## Install dependencies and virtual environment

* sudo apt-get install python libexpat1 
* sudo apt-get install apache2 apache2-utils ssl-cert
 
* sudo apt install apache2
* sudo apt-get install libapache2-mod-wsgi-py3

** sudo apt-get install libapache2-mod-wsgi
** sudo apt-get remove libapache2-mod-python libapache2-mod-wsgi

*	sudo apt install php libapache2-mod-php
*	sudo systemctl restart apache2

*	sudo git clone https://github.com/Avensky/WebDeveloper.git /var/www/html/WebDeveloper
*	sudo apt-get install python3-venv
*	sudo python3 -m venv venv
*	source /var/www/html/WebDeveloper/venv/bin/activate

* sudo apt-get install python-pip
* sudo apt install python3-pip
* sudo pip3 install flask
* sudo pip3 install Flask-SQLAlchemy
* sudo apt-get install python3-psycopg2
* sudo apt install python3-oauth2client

*	sudo python2 -m pip install requests
*	sudo python2 -m pip install httplib2	
*	sudo apt-get -qqy install postgresql python-psycopg2

## Configure Apache, mod-wsgi
*	sudo nano /etc/apache2/sites-available/000-default.conf
*	sudo nano /etc/apache2/sites-available/WebDeveloper.conf
**		<VirtualHost *:80>
**			ServerName urielzacarias.com
**			ServerAdmin urielzacarias@gmail.com
**			WSGIScriptAlias / /var/www/html/WebDeveloper/myapp.wsgi
**			<Directory /var/www/html/WebDeveloper>
**				Order allow,deny
**				Allow from all
**			</Directory>
**			
**			Alias /static /var/www/html/WebDeveloper/static
**			<Directory /var/www/html/WebDeveloper/static/>
**				Order allow,deny
**				Allow from all
**			</Directory>
**			
**			ErrorLog ${APACHE_LOG_DIR}/error.log
**			LogLevel warn
**			CustomLog ${APACHE_LOG_DIR}/access.log combined
**		</VirtualHost>
		
* sudo a2ensite WebDeveloper
* sudo systemctl reload apache2
* sudo apache2ctl configtest
* sudo nano /var/www/html/WebDeveloper/myapp.wsgi
**		#!/usr/bin/python
**		import sys
**		import logging
**		sys.path.append('/var/www/html/WebDeveloper')
**		from __init__ import app as application
**		application.secret_key = 'super_secret_key'
* sudo service apache2 restart


## Install and configure postgreSQL database and user
* sudo apt-get install postgresql 
* sudo apt-get install python-sqlalchemy
* Do not allow remote connections
* sudo nano /etc/postgresql/9.5/main/pg_hba.conf

* sudo su postgres
* createuser --interactive --pwprompt
** Enter name of role to add: developer
** Enter password for new role: 86developers
** Enter it again:
** Shall the new role be a superuser? (y/n) n
** Shall the new role be allowed to create databases? (y/n) y
** Shall the new role be allowed to create more new roles? (y/n) n
** createdb -O develper myDatabase
*	exit
* psql postgres
** DROP USER 
	
			
* sudo nano /var/www/html/WebDeveloper/database_setup.py
* sudo python database_setup.py
* sudo service apache2 restart

* sudo nano /etc/hosts
* 54.200.79.28 avensky.com

## Configure and install software to enable HTTPS 
* sudo apt-get update
* sudo apt-get install software-properties-common
* sudo add-apt-repository universe
* sudo add-apt-repository ppa:certbot/certbot
* sudo apt-get update

* sudo apt-get install certbot python-certbot-apache
* sudo certbot --apache

	/etc/letsencrypt/live/www.avensky.com/privkey.pem
	
	sudo crontab -e
	1
	30 4 1 * * sudo certbot renew --quiet
	
	 sudo nano /var/log/apache2/error.log
	 sudo nano /etc/apache2/apache2.con
	 
sudo apachectl -k restart
sudo tail -n 5 /var/log/apache2/error.log
sudo nano /var/log/apache2/error.log

