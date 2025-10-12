import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from config import app

db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_user_id(self):
        return self.id

# Outh 2.0 Database Model
# Client Model
class OAuth2Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(48), unique=True, nullable=False)
    client_secret = db.Column(db.String(120))
    client_id_issued_at = db.Column(db.Integer, nullable=False, default=0)
    client_secret_expires_at = db.Column(db.Integer, nullable=False, default=0)
    client_metadata = db.Column(db.Text)

# Token Model
class OAuth2Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    client_id = db.Column(db.String(48), nullable=False)
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    scope = db.Column(db.Text, default='')
    revoked = db.Column(db.Boolean, default=False)
    
    def is_expired(self):
        return datetime.datetime.utcnow() > self.expires_at
    
    def is_revoked(self):
        return self.revoked
    
    def is_valid(self):
        return not self.is_expired() and not self.is_revoked()
    
    def get_scope(self):  # Add this method for Authlib compatibility
        return self.scope or ''