import os
import sys
import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask import Flask
from flask_login import UserMixin, LoginManager

Base = declarative_base()


class User(Base, UserMixin):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(20), unique=True, nullable=False)
    email = Column(String(120),  unique=True, nullable=False)
    image_file = Column(String(20), nullable=False, default='blank_user.gif')
    password = Column(String(60), nullable=False)
    posts = relationship('Post', backref='author', lazy=True)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'username': self.username,
            'name': self.name,
            'email': self.email,
            'picture': self.picture,
            'password': self.password,
            'post': self.posts
        }

class Post(Base):
    __tablename__= 'post'

    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    date_posted = Column(DateTime, nullable=False, default=datetime.datetime.utcnow())
    content = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'title': self.title,
            'date_posted': self.date_posted,
            'content': self.content,
            'user_id': self.user_id
        }

engine = create_engine('sqlite:///webdev.db')
# engine = create_engine('postgresql://developer:86developers@localhost:5432/myDatabase')

Base.metadata.create_all(engine)
