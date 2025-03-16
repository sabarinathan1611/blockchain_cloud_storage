from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
import secrets
from datetime import datetime
from secrets import token_bytes
from Crypto.Random import get_random_bytes


class Text(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_Key = db.Column(db.LargeBinary, nullable=False)  
    nonce = db.Column(db.LargeBinary, nullable=False)  
    ciphertext = db.Column(db.LargeBinary, nullable=False)  
    private_key_path = db.Column(db.LargeBinary, nullable=False)  
    public_key_path = db.Column(db.LargeBinary, nullable=False)  
    store_type = db.Column(db.LargeBinary, nullable=False)  
    date = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.LargeBinary,nullable=True)
    email = db.Column(db.LargeBinary, unique=True,nullable=True)
    password = db.Column(db.String(), nullable=False)
    texts = db.relationship('Text', backref='user', lazy=True)
    files = db.relationship('File', backref='user', lazy=True)
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    role =  db.Column(db.String(),nullable=False,default='user')
    path=db.Column(db.LargeBinary, unique=True)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(), default=secrets.token_urlsafe)
    used_storage=db.Column(db.Integer,default=0)
    salt = db.Column(db.LargeBinary(16), default=get_random_bytes(16))
    limited_storage=db.Column(db.Integer,nullable=False,default=209715)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.LargeBinary, unique=True, nullable=True)  # Store as bytes
    filepath = db.Column(db.LargeBinary, unique=True, nullable=True)  # Store as bytes
    private_key_path = db.Column(db.LargeBinary, unique=True, nullable=True)  # Store as bytes
    public_key_path = db.Column(db.LargeBinary, unique=True, nullable=True)  # Store as bytes
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mimetype = db.Column(db.LargeBinary, nullable=True)  # Store as bytes
    decryptedLists = db.Column(db.LargeBinary, nullable=True)  # Store as bytes
    status = db.Column(db.Text(100))  
    iv = db.Column(db.LargeBinary, nullable=False)  # Store as bytes
    encrypted_key = db.Column(db.LargeBinary, nullable=False)  # Store as bytes
    date = db.Column(db.DateTime(timezone=True), default=func.now())


class DeleteAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)  
    email = db.Column(db.LargeBinary, unique=True,nullable=False)
    deleted=db.Column(db.Boolean, default=False)

class Feedback(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.LargeBinary, unique=True,nullable=True)
    email= db.Column(db.LargeBinary, unique=True,nullable=True)
    text = db.Column(db.LargeBinary, unique=True,nullable=True)
    fixed=db.Column(db.Boolean, default=False)
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    