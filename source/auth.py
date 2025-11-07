''' External Library Import '''
from authlib.integrations.flask_oauth2 import ResourceProtector, AuthorizationServer
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6749 import grants
import datetime

''' Internal File Import '''
from dbModel import db, OAuth2Token, User, OAuth2Client
from config import app


# OAuth 2.0 Configuration
require_oauth = ResourceProtector()

# Custom Token Validator
class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        token = OAuth2Token.query.filter_by(access_token=token_string).first()
        if token and token.is_valid():
            return token
        return None

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