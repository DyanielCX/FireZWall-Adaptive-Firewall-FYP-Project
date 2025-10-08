from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api, reqparse
import subprocess
from authlib.integrations.flask_oauth2 import ResourceProtector, AuthorizationServer
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6750 import BearerTokenValidator
from werkzeug.security import gen_salt, generate_password_hash, check_password_hash
import datetime

# Setup Flask, Database, REST API
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firewallx_oauth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production!
db = SQLAlchemy(app)
api = Api(app)

# OAuth 2.0 Configuration
require_oauth = ResourceProtector()

# Simplified Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_user_id(self):
        return self.id

class OAuth2Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(48), unique=True, nullable=False)
    client_secret = db.Column(db.String(120))
    client_id_issued_at = db.Column(db.Integer, nullable=False, default=0)
    client_secret_expires_at = db.Column(db.Integer, nullable=False, default=0)
    client_metadata = db.Column(db.Text)

class OAuth2Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    client_id = db.Column(db.String(48), nullable=False)
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    scope = db.Column(db.Text, default='')
    is_revoked = db.Column(db.Boolean, default=False)
    
    def is_expired(self):
        return datetime.datetime.utcnow() > self.expires_at
    
    def is_valid(self):
        return not self.is_expired() and not self.is_revoked

# Custom Token Validator
class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        token = OAuth2Token.query.filter_by(access_token=token_string).first()
        if token and token.is_valid():
            return token
        return None
    
    def request_invalid(self, request):
        return False
    
    def token_revoked(self, token):
        return token.is_revoked

# Register the token validator
require_oauth.register_token_validator(MyBearerTokenValidator())

# OAuth 2.0 Grant Implementation
class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']
    
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            return user
        return None

# OAuth 2.0 Configuration Functions
def query_client(client_id):
    return OAuth2Client.query.filter_by(client_id=client_id).first()

def save_token(token_data, request):
    if not hasattr(request, 'user') or not request.user:
        return None
    
    user_id = request.user.get_user_id()
    
    token = OAuth2Token(
        client_id=request.client.client_id,
        user_id=user_id,
        access_token=token_data.get('access_token'),
        refresh_token=token_data.get('refresh_token'),
        token_type=token_data.get('token_type', 'Bearer'),
        scope=token_data.get('scope', '')
    )
    
    if 'expires_in' in token_data:
        token.expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=token_data['expires_in'])
    
    db.session.add(token)
    db.session.commit()
    return token

# Initialize OAuth2
authorization = AuthorizationServer(app, query_client=query_client, save_token=save_token)
authorization.register_grant(PasswordGrant)

# Create default client and user
def init_database():
    try:
        # Create all tables
        db.create_all()
        print("Database tables created successfully!")
        
        # Create a default OAuth client
        if not OAuth2Client.query.first():
            client = OAuth2Client(
                client_id='default-client',
                client_secret='default-secret',
                client_id_issued_at=int(datetime.datetime.utcnow().timestamp()),
                client_metadata='{"scope": "firewall", "grant_types": ["password"]}'
            )
            db.session.add(client)
            
            # Create a default admin user
            if not User.query.filter_by(username='admin').first():
                admin_user = User(
                    username='admin',
                    email='admin@firewallx.com'
                )
                admin_user.set_password('admin123')
                db.session.add(admin_user)
            
            db.session.commit()
            print("Default client and user created successfully!")
        else:
            print("Default client and user already exist!")
            
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.session.rollback()

# Authentication Endpoints
class Login(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('client_id', type=str, required=False, default='default-client')
        parser.add_argument('client_secret', type=str, required=False, default='default-secret')
        
        args = parser.parse_args()
        
        # Get client
        client = OAuth2Client.query.filter_by(client_id=args['client_id']).first()
        if not client or client.client_secret != args['client_secret']:
            return {'error': 'invalid_client'}, 401
        
        # Authenticate user
        user = User.query.filter_by(username=args['username']).first()
        if not user or not user.check_password(args['password']) or not user.is_active:
            return {'error': 'invalid_credentials'}, 401
        
        # Generate token
        try:
            access_token = gen_salt(48)
            refresh_token = gen_salt(48)
            expires_in = 3600  # 1 hour
            
            # Save token to database
            token_record = OAuth2Token(
                access_token=access_token,
                refresh_token=refresh_token,
                user_id=user.id,
                client_id=client.client_id,
                token_type='Bearer',
                expires_at=datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in),
                scope='firewall'
            )
            db.session.add(token_record)
            db.session.commit()
            
            return jsonify({
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": expires_in,
                "refresh_token": refresh_token,
                "user_id": user.id
            })
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

class Register(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('email', type=str, required=True, help='Email is required')
        
        args = parser.parse_args()
        
        # Check if user already exists
        if User.query.filter_by(username=args['username']).first():
            return {'error': 'Username already exists'}, 400
        
        if User.query.filter_by(email=args['email']).first():
            return {'error': 'Email already exists'}, 400
        
        # Create new user
        user = User(
            username=args['username'],
            email=args['email']
        )
        user.set_password(args['password'])
        
        try:
            db.session.add(user)
            db.session.commit()
            return {'message': 'User created successfully'}, 201
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

class RefreshToken(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('refresh_token', type=str, required=True, help='Refresh token is required')
        parser.add_argument('client_id', type=str, required=False, default='default-client')
        parser.add_argument('client_secret', type=str, required=False, default='default-secret')
        
        args = parser.parse_args()
        
        # Verify client
        client = OAuth2Client.query.filter_by(client_id=args['client_id']).first()
        if not client or client.client_secret != args['client_secret']:
            return {'error': 'invalid_client'}, 401
        
        # Verify refresh token
        token = OAuth2Token.query.filter_by(refresh_token=args['refresh_token']).first()
        if not token or token.is_expired() or token.is_revoked:
            return {'error': 'invalid_refresh_token'}, 401
        
        # Generate new token
        new_access_token = gen_salt(48)
        new_refresh_token = gen_salt(48)
        expires_in = 3600
        
        # Update token in database
        token.access_token = new_access_token
        token.refresh_token = new_refresh_token
        token.expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
        token.is_revoked = False  # Ensure the new token is not revoked
        
        try:
            db.session.commit()
            return jsonify({
                "access_token": new_access_token,
                "token_type": "bearer", 
                "expires_in": expires_in,
                "refresh_token": new_refresh_token
            })
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

class Logout(Resource):
    @require_oauth()  # Requires valid OAuth token
    def post(self):
        try:
            # Get the current token from the request context
            # Authlib should set this when the token is validated
            current_token = getattr(g, 'oauth2_token', None)
            
            if not current_token:
                return {'error': 'No token found in request'}, 400
            
            # Revoke the current access token
            token = OAuth2Token.query.filter_by(access_token=current_token.access_token).first()
            if token:
                token.is_revoked = True
                db.session.commit()
                return {'message': 'Successfully logged out'}, 200
            else:
                return {'error': 'Token not found'}, 404
                
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

class LogoutAll(Resource):
    @require_oauth()  # Requires valid OAuth token
    def post(self):
        try:
            # Get the current user ID from the token
            current_token = getattr(g, 'oauth2_token', None)
            
            if not current_token:
                return {'error': 'No token found in request'}, 400
            
            user_id = current_token.user_id
            
            # Revoke all tokens for this user
            tokens = OAuth2Token.query.filter_by(user_id=user_id, is_revoked=False).all()
            for token in tokens:
                token.is_revoked = True
            
            db.session.commit()
            return {'message': f'Successfully logged out from all devices. {len(tokens)} tokens revoked.'}, 200
                
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

# Protected Firewall Resource
class Firewall(Resource):
    @require_oauth()  # Requires valid OAuth token
    def post(self, port):
        try:
            # Build and run the ufw command
            cmd = ["sudo", "/usr/sbin/ufw", "allow", f"{port}/tcp"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return jsonify({
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @require_oauth()  # Requires valid OAuth token
    def delete(self, port):
        try:
            # Build and run the ufw command
            cmd = ["sudo", "/usr/sbin/ufw", "delete", f"{port}"]
            result = subprocess.run(cmd, input="y", capture_output=True, text=True)
            
            return jsonify({
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

# API Routes
api.add_resource(Login, '/api/login')
api.add_resource(Register, '/api/register')
api.add_resource(RefreshToken, '/api/refresh-token')
api.add_resource(Logout, '/api/logout')
api.add_resource(LogoutAll, '/api/logout-all')
api.add_resource(Firewall, '/api/firewall/<int:port>')

@app.route('/')
def index():
    return '<h1>Flask REST API with OAuth 2.0</h1>'

@app.route('/api/test-db')
def test_db():
    try:
        user_count = User.query.count()
        client_count = OAuth2Client.query.count()
        return jsonify({
            'users': user_count,
            'clients': client_count,
            'status': 'Database connected successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Initialize database and create default data
    with app.app_context():
        init_database()
    app.run(host="0.0.0.0", port=5000, debug=True)