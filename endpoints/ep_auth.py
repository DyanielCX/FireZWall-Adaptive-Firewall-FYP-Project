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
            # ---  Logs Record --- #
            # Define the webapp if ip_addr is localhost
            if request.remote_addr == "127.0.0.1":
                current_ip = "127.0.0.1 (webapp)"
            else:
                current_ip = request.remote_addr

            # Log info
            level = "WARNING"
            event_type = "AUTH_LOGIN_FAILED"
            module = "auth"
            message = "Invalid client"
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/login"
            details = request.get_json()

            syslog_create(level, event_type, module, message, None, ip_addr, method, endpoint, details)
            
            return {'error': 'invalid_client'}, 405
        
        # Authenticate user
        user = User.query.filter_by(username=args['username']).first()
        if not user or not user.check_password(args['password']) or not user.is_active:
            # --- Logs Record --- #
            # Define the webapp if ip_addr is localhost
            if request.remote_addr == "127.0.0.1":
                current_ip = "127.0.0.1 (webapp)"
            else:
                current_ip = request.remote_addr

            # Log info
            level = "WARNING"
            event_type = "AUTH_LOGIN_FAILED"
            module = "auth"
            message = f"Invalid password [{args['username']}/{args['password']}]"
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/login"
            details = request.get_json()

            syslog_create(level, event_type, module, message, None, ip_addr, method, endpoint, details)

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
                scope=user.role
            )
            db.session.add(token_record)
            db.session.commit()

            # --- Logs Record --- #
            # Define the webapp if ip_addr is localhost
            if request.remote_addr == "127.0.0.1":
                current_ip = "127.0.0.1 (webapp)"
            else:
                current_ip = request.remote_addr

            # Log info
            level = "INFO"
            event_type = "AUTH_LOGIN_SUCCESS"
            module = "auth"
            message = f"User({args['username']}) login succeed"
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/login"
            details = request.get_json()

            syslog_create(level, event_type, module, message, None, ip_addr, method, endpoint, details)
            
            return jsonify({
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": expires_in,
                "refresh_token": refresh_token
            })
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
            # --- Logs Record --- #
            # Get the OAuth token & username
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            Username = get_username_with_token(access_token)

            # Define the webapp if ip_addr is localhost
            if request.remote_addr == "127.0.0.1":
                current_ip = "127.0.0.1 (webapp)"
            else:
                current_ip = request.remote_addr
            
            ## Log info
            level = "WARNING"
            event_type = "TOKEN_REFRESH_FAILED"
            module = "auth"
            message = "Invalid client"
            username = Username
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/refresh-token"
            details = request.get_json()

            syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
            
            return {'error': 'invalid_client'}, 401
        
        # Verify refresh token
        token = OAuth2Token.query.filter_by(refresh_token=args['refresh_token']).first()
        if not token or token.is_revoked():         
            # --- Logs Record --- #
            # Get the OAuth token & username
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            Username = get_username_with_token(access_token)
            
            # Define the webapp if ip_addr is localhost
            if request.remote_addr == "127.0.0.1":
                current_ip = "127.0.0.1 (webapp)"
            else:
                current_ip = request.remote_addr

            # Log info
            level = "WARNING"
            event_type = "TOKEN_REFRESH_FAILED"
            module = "auth"
            message = "Invalid refresh token"
            username = Username
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/refresh-token"
            details = request.get_json()

            syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
            
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

            # --- Logs Record --- #
            # Get the username
            Username = get_username_with_token(new_access_token)

            # Define the webapp if ip_addr is localhost
            if request.remote_addr == "127.0.0.1":
                current_ip = "127.0.0.1 (webapp)"
            else:
                current_ip = request.remote_addr

            # Log info
            level = "INFO"
            event_type = "TOKEN_REFRESH_SUCCESS"
            module = "auth"
            message = f"User({Username})'s token refresh succeed"
            username = Username
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/refresh-token"
            details = request.get_json()

            syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
            
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
    @require_oauth()
    def post(self):
        try:
            # Get the authorization header
            auth_header = request.headers.get('Authorization')
           
            # Extract the token from the header
            access_token = auth_header.split(' ')[1]
            
            # Find and revoke the token
            token = OAuth2Token.query.filter_by(access_token=access_token).first()
            if token:
                # Revoke token
                token.revoked = True
                db.session.commit()

                # --- Logs Record --- #
                # Get the OAuth token & username
                auth_header = request.headers.get('Authorization')
                access_token = auth_header.split(' ')[1]
                Username = get_username_with_token(access_token)

                # Define the webapp if ip_addr is localhost
                if request.remote_addr == "127.0.0.1":
                    current_ip = "127.0.0.1 (webapp)"
                else:
                    current_ip = request.remote_addr

                # Log info
                level = "INFO"
                event_type = "AUTH_LOGOUT_SUCCESS"
                module = "auth"
                message = f"User({Username}) logout succeed [one token revoke]"
                username = Username
                ip_addr = current_ip
                method = "POST"
                endpoint = "/api/logout"
                details = {"Authorization": f"Bearer {access_token}"}

                syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

                return {'message': 'Successfully logged out'}, 200
                
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

# Logout All Devices Endpoints
class LogoutAll(Resource):
    @require_oauth()
    def post(self):
        try:
            # Get the authorization header to identify the current user
            auth_header = request.headers.get('Authorization')
            
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

            # --- Logs Record --- #
            # Get the OAuth token & username
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            Username = get_username_with_token(access_token)

            # Define the webapp if ip_addr is localhost
            if request.remote_addr == "127.0.0.1":
                current_ip = "127.0.0.1 (webapp)"
            else:
                current_ip = request.remote_addr

            # Log info
            level = "INFO"
            event_type = "AUTH_LOGOUT_SUCCESS"
            module = "auth"
            message = f"User({Username}) logout succeed [{len(tokens)} token revoke]"
            username = Username
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/logout-all"
            details = {"Authorization": f"Bearer {access_token}"}

            syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

            return {'message': f'Successfully logged out from all devices. {len(tokens)} tokens revoked.'}, 200
                
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500