''' External Library Import '''
from authlib.integrations.flask_oauth2 import ResourceProtector, AuthorizationServer
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6749 import grants, scope_to_list
from flask import request, g
from functools import wraps
import datetime

''' Internal File Import '''
from dbModel import db, OAuth2Token, User, OAuth2Client
from source.syslog_record import syslog_create, get_username_with_token
from config import app


# OAuth 2.0 Configuration
require_oauth = ResourceProtector()

# Custom Token Validator
class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        token = OAuth2Token.query.filter_by(access_token=token_string).first()
        if token and token.is_valid():
            return token

       # ---Logs Record--- #
       # Log info
        level = "WARNING"
        event_type = "INVALID_TOKEN"
        module = "auth"
        message = "Invalid token"
        ip_addr = request.remote_addr
        method = request.method
        endpoint = request.path
        details = {"Authorization": f"Bearer {token_string}"}

        syslog_create(level, event_type, module, message, None, ip_addr, method, endpoint, details)
        
        return None

# Register the token validator
require_oauth.register_token_validator(MyBearerTokenValidator())

# Token checker with scope
def require_oauth_with_scope(*scopes):
    def wrapper(f):
        @wraps(f)
        @handle_oauth_errors
        def decorated(*args, **kwargs):
            # Let Authlib handle token validation and basic scope checking
            token = require_oauth.acquire_token()
            if not token:
                return {
                    "success": False,
                    "error": "Invalid token"
                }, 401
            
            # Check if token has ANY of the required scopes (OR logic)
            token_scopes = set(scope_to_list(token.get_scope()))
            required_scopes = set(scopes)
            
            if not token_scopes.intersection(required_scopes):
                # ---Logs Record--- #
                # Get the OAuth token & username
                auth_header = request.headers.get('Authorization')
                access_token = auth_header.split(' ')[1]
                Username = get_username_with_token(access_token)
                
                # Log info
                level = "WARNING"
                event_type = "ACCESS_DENIED"
                module = "auth"
                message = f"Access denied for endpoint({request.path})"
                username = Username
                ip_addr = request.remote_addr
                method = request.method
                endpoint = request.path
                details = {"Authorization": f"Bearer {access_token}"}

                syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
                
                return {
                    "success": False,
                    "error": f"Access denied. This endpoint only allow for {', '.join(scopes)}"
                }, 403
            
            return f(*args, **kwargs)
        return decorated
    return wrapper

def handle_oauth_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:          
            return {
                "message": None
            }, 401
    return decorated_function

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
        scope=token_data.get('scope', 'firewall')
    )
    
    if 'expires_in' in token_data:
        token.expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=token_data['expires_in'])
    
    db.session.add(token)
    db.session.commit()
    return token

# Initialize OAuth2
authorization = AuthorizationServer(app, query_client=query_client, save_token=save_token)
authorization.register_grant(PasswordGrant)