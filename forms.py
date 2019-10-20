from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User

engine = create_engine('sqlite:///webdev.db')
#engine = create_engine('postgresql://developer:86developers@localhost/myDatabase')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


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
