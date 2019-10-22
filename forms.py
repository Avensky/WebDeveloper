from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User
from flask_login import current_user

################################################################################
################################################################################
# connect to db
################################################################################
################################################################################
engine = create_engine('sqlite:///webdev.db',connect_args={'check_same_thread': False})
# engine = create_engine('postgresql://developer:86developers@localhost:5432/myDatabase')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


################################################################################
################################################################################
# forms
################################################################################
################################################################################
class RegistrationForm(FlaskForm):
    username = StringField('Username:',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email:',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password:',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = session.query(User).filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please Choose a different one.')

    def validate_email(self, email):
#        user = User.query.filter_by(email=email.data).first()
        user = session.query(User).filter_by(email=email.data).first()

        if user:
            raise ValidationError('That email is taken. Please Choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email:',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username:',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email:',
                        validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'gif'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = session.query(User).filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please Choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
#           user = User.query.filter_by(email=email.data).first()
            user = session.query(User).filter_by(email=email.data).first()

            if user:
                raise ValidationError('That email is taken. Please Choose a different one.')
