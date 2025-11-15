''' External Library Import '''
from flask import request, jsonify
from flask_restful import Resource, reqparse
from werkzeug.security import gen_salt
import datetime

''' Internal File Import '''
from dbModel import db, User, OAuth2Client, OAuth2Token
from source.auth import require_oauth
from source.syslog_record import syslog_create, get_username_with_token


## Authentication Endpoints ##
# Login Endpoint
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
            # # Logs Record
            # level = "WARNING"
            # event_type = "AUTH_LOGIN_FAILED"
            # module = "auth"
            # message = "Invalid client"
            # username = args['username']
            # ip_addr = request.remote_addr
            # method = "POST"
            # endpoint = "/api/login"
            # details = request.get_json

            # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
            
            return {'error': 'invalid_client'}, 405
        
        # Authenticate user
        user = User.query.filter_by(username=args['username']).first()
        if not user or not user.check_password(args['password']) or not user.is_active:
            # # Logs Record
            # level = "WARNING"
            # event_type = "AUTH_LOGIN_FAILED"
            # module = "auth"
            # message = "Invalid password"
            # username = args['username']
            # ip_addr = request.remote_addr
            # method = "POST"
            # endpoint = "/api/login"
            # details = request.get_json

            # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

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

            # # Logs Record
            # level = "INFO"
            # event_type = "AUTH_LOGIN_SUCCESS"
            # module = "auth"
            # message = f"User '{args['username']}' login succeed"
            # username = args['username']
            # ip_addr = request.remote_addr
            # method = "POST"
            # endpoint = "/api/login"
            # details = request.get_json

            # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
            
            return jsonify({
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": expires_in,
                "refresh_token": refresh_token
            })
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

# Register Endpoint
class Register(Resource):

    @require_oauth()  # Requires valid OAuth token
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        
        args = parser.parse_args()
        
        # Check if user already exists
        if User.query.filter_by(username=args['username']).first():
            
            # # Logs Record
            # level = "INFO"
            # event_type = "USER_REGISTER_FAILED"
            # module = "auth"
            # message = "Register existed username user"
            # ip_addr = request.remote_addr
            # method = "POST"
            # endpoint = "/api/register"
            # details = request.get_json

            # syslog_create(level, event_type, module, message, None, ip_addr, method, endpoint, details)
            
            return {'error': 'Username already exists'}, 400
        
        # Create new user
        user = User(
            username=args['username'],
        )
        user.set_password(args['password'])
        
        try:
            db.session.add(user)
            db.session.commit()

            # # Get the OAuth token & username
            # auth_header = request.headers.get('Authorization')
            # access_token = auth_header.split(' ')[1]
            # Username = get_username_with_token(access_token)

            # # Logs Record
            # level = "INFO"
            # event_type = "USER_REGISTER_SUCCESS"
            # module = "auth"
            # message = f"User '{args['username']}' register succeed"
            # username = Username
            # ip_addr = request.remote_addr
            # method = "POST"
            # endpoint = "/api/register"
            # details = request.get_json

            # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

            return {'message': 'User created successfully'}, 201
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

# Refresh Token Endpoints
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
        if not token or token.is_revoked():
            return {'error': 'invalid_refresh_token'}, 401
        
        # Generate new token
        new_access_token = gen_salt(48)
        new_refresh_token = gen_salt(48)
        expires_in = 3600
        
        # Update token in database
        token.access_token = new_access_token
        token.refresh_token = new_refresh_token
        token.expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
        token.revoked = False  # Ensure the new token is not revoked
        
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

# Logout Endpoints
class Logout(Resource):
    @require_oauth()  # Requires valid OAuth token
    def post(self):
        try:
            # Get the authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return {'error': 'Invalid authorization header'}, 400
            
            # Extract the token from the header
            access_token = auth_header.split(' ')[1]
            
            # Find and revoke the token
            token = OAuth2Token.query.filter_by(access_token=access_token).first()
            if token:
                token.revoked = True
                db.session.commit()
                return {'message': 'Successfully logged out'}, 200
            else:
                return {'error': 'Token not found'}, 404
                
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

# Logout All Devices Endpoints
class LogoutAll(Resource):
    @require_oauth()  # Requires valid OAuth token
    def post(self):
        try:
            # Get the authorization header to identify the current user
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return {'error': 'Invalid authorization header'}, 400
            
            # Extract the token from the header
            access_token = auth_header.split(' ')[1]
            
            # Find the current token to get user_id
            current_token = OAuth2Token.query.filter_by(access_token=access_token).first()
            if not current_token:
                return {'error': 'Token not found'}, 404
            
            user_id = current_token.user_id
            
            # Revoke all tokens for this user
            tokens = OAuth2Token.query.filter_by(user_id=user_id, revoked=False).all()
            for token in tokens:
                token.revoked = True
            
            db.session.commit()
            return {'message': f'Successfully logged out from all devices. {len(tokens)} tokens revoked.'}, 200
                
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500