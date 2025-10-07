# app.py
import os
import json
import time
import ipaddress
import secrets
import subprocess
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector, current_token
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin, OAuth2TokenMixin,
    create_query_client_func, create_bearer_token_validator
)
from authlib.oauth2.rfc6749 import grants

# # Allow HTTP for local dev (remove in production!)
# os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firewallx_oauth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ----------------- MODELS -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class OAuth2Client(db.Model, OAuth2ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=True)
    user = db.relationship('User')
    client_ip = db.Column(db.String(45), nullable=True)

# ----------------- AUTHLIB -----------------
query_client = create_query_client_func(db.session, OAuth2Client)

def save_token(token_data, request):
    now = int(time.time())
    expires_in = token_data.get('expires_in')
    t = OAuth2Token(
        client_id=request.client.client_id if request.client else None,
        user_id=request.user.id if getattr(request, 'user', None) else None,
        access_token=token_data.get('access_token'),
        refresh_token=token_data.get('refresh_token'),
        scope=token_data.get('scope'),
        issued_at=now,
        expires_in=expires_in,
        expires_at=now + expires_in if expires_in else None,
        revoked=False,
        client_ip=request.remote_addr
    )
    db.session.add(t)
    db.session.commit()

authorization = AuthorizationServer(app, query_client=query_client, save_token=save_token)

# Password grant
class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        return user if user and user.check_password(password) else None

authorization.register_grant(PasswordGrant)
authorization.register_grant(grants.RefreshTokenGrant)

require_oauth = ResourceProtector()
bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
require_oauth.register_token_validator(bearer_cls())

# ----------------- HELPERS -----------------
def require_token_and_ip(f):
    @wraps(f)
    @require_oauth()
    def decorated(*args, **kwargs):
        g.current_user = current_token.user
        return f(*args, **kwargs)
    return decorated

# ----------------- ROUTES -----------------
@app.route('/oauth/token', methods=['POST'])
def issue_token():
    """Issue token - expect JSON request"""
    if request.is_json:
        # Convert JSON to form-data format for Authlib
        body = request.get_json()
        request.form = request.form.copy()
        for k, v in body.items():
            request.form[k] = v
    return authorization.create_token_response()

@app.route('/oauth/revoke', methods=['POST'])
def revoke():
    data = request.get_json() or {}
    token_str = data.get('token')
    if not token_str:
        return jsonify({"success": False, "error": "token_required"}), 400
    token = OAuth2Token.query.filter(
        (OAuth2Token.access_token == token_str) | (OAuth2Token.refresh_token == token_str)
    ).first()
    if not token:
        return jsonify({"success": False, "error": "token_not_found"}), 404
    token.revoked = True
    db.session.commit()
    return jsonify({"success": True, "message": "Token revoked"})

@app.route('/firewall/add_rule', methods=['POST'])
@require_token_and_ip
def add_rule():
    """Add firewall rule via JSON body"""
    data = request.get_json() or {}
    action = data.get("action")
    port = data.get("port")
    proto = data.get("proto", "tcp")

    if action not in ("allow", "deny", "reject"):
        return jsonify({"success": False, "error": "invalid_action"}), 400
    if not isinstance(port, int):
        return jsonify({"success": False, "error": "invalid_port"}), 400

    cmd = ["sudo", "/usr/sbin/ufw", action, f"{port}/{proto}"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    return jsonify({
        "success": True,
        "applied_by": g.current_user.username,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip()
    })

@app.route('/')
def index():
    return '<h1>Flask REST API</h1>'
    

# ----------------- INIT -----------------
@app.cli.command("init-db")
def init_db():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        u = User(username="admin")
        u.set_password("password123")
        db.session.add(u)
        db.session.commit()
        print("Created user: admin / password123")

    if not OAuth2Client.query.filter_by(client_id="client1").first():
        client = OAuth2Client(
            client_id="client1",
            client_secret=secrets.token_urlsafe(24),
            user_id=1
        )
        client.set_client_metadata({
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["password", "refresh_token"],
            "response_types": [],
            "scope": "all"
        })
        db.session.add(client)
        db.session.commit()
        print("Created client: client1 (secret stored in DB)")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # app.run(host="0.0.0.0", port=5000, debug=True)
    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=('SSL_cert/cert.pem', 'SSL_cert/key.pem'))
