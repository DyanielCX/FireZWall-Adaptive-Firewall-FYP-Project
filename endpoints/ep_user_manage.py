''' External Library Import '''
from flask_restful import Resource, reqparse
from flask import request


''' Internal File Import '''
from dbModel import db, User, OAuth2Token
from source.auth import require_oauth, require_oauth_with_scope
from source.syslog_record import syslog_create, get_username_with_token
        

# View User Endpoint
class ViewUser(Resource):
    @require_oauth_with_scope('admin') # Admin only access
    def get(self):
        
        parser = reqparse.RequestParser()
        parser.add_argument('role', type=str, required=False, choices=['admin', 'dev', 'cybersec', 'user'], help='Role (admin, dev, cybersec, user)')

        args = parser.parse_args()
        query = User.query

        # =============
        #   Filtering
        # =============

        ## Role filtering ##
        role = args.get("role")

        if role:
            query = query.filter_by(role=role)
        
        
        ## Pagination ##
        limit = int(args.get("limit", 50))
        offset = int(args.get("offset", 0))
        items = query.order_by(User.id.desc()).offset(offset).limit(limit).all()
        
        results = [{
                    "id": e.id,
                    "username": e.username,
                    "password_hash": e.password_hash,
                    "role": e.role,
                    "created_at": e.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "is_active": e.is_active,
                }for e in items]
        
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
        event_type = "VIEW_USER_LIST_SUCCESS"
        module = "auth"
        message = f"View the user list succeed"
        username = Username
        ip_addr = current_ip
        method = "GET"
        endpoint = "/api/user/view"
        details = request.get_json()

        syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

        return {
            "success": True,
            "count": len(results),
            "users": results
        }
    

# Register User Endpoint
class Register(Resource):
    @require_oauth_with_scope('admin')
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        parser.add_argument('role', type=str, required=False, default='user', help='Role (admin/dev/user)')
        
        args = parser.parse_args()
        
        # Check if user already exists
        if User.query.filter_by(username=args['username']).first():
            
            # --- Logs Record --- #
            # Get the OAuth token & username (Admin acc)
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
            event_type = "USER_REGISTER_FAILED"
            module = "auth"
            message = "Register existed username user"
            username = Username
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/user/register"
            details = request.get_json()

            syslog_create(level, event_type, module, message, Username, ip_addr, method, endpoint, details)
            
            return {
                "success": False,
                'error': 'Username already exists'
            }, 400
        
        # Create new user
        user = User(
            username=args['username'],
            role = args['role']
        )
        user.set_password(args['password'])
        
        try:
            db.session.add(user)
            db.session.commit()

            # --- Logs Record --- #
            # Get the OAuth token & username (Admin acc)
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
            event_type = "USER_REGISTER_SUCCESS"
            module = "auth"
            message = f"User({args['username']}) register succeed"
            username = Username
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/user/register"
            details = request.get_json()

            syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

            return {
                "success": True,
                'message': 'User created successfully'
            }, 201
        except Exception as e:
            db.session.rollback()
            return {
                "success": False,
                'error': str(e)
            }, 500


# Delete User Endpoint
class DeleteUser(Resource):
    @require_oauth_with_scope('admin')
    def delete(self):
        
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username')

        args = parser.parse_args()
        query = User.query

        # =============
        #   Filtering
        # =============

        ## Role filtering ##
        username_to_delete  = args.get("username")

        # Get current user from token
        auth_header = request.headers.get('Authorization')
        access_token = auth_header.split(' ')[1]
        current_username = get_username_with_token(access_token)
        
        try:
            # Input validation
            if not username_to_delete or username_to_delete.strip() == '':
                return {
                    "success": False,
                    "message": "Username cannot be empty"
                }, 400
            
            # Find the user to delete
            user_to_delete = User.query.filter_by(username=username_to_delete).first()
            
            if not user_to_delete:           
                return {
                    "success": False,
                    "message": f"User({username_to_delete}) does not exist"
                }, 404
            
            # Safety checks
            if current_username == username_to_delete:
                return {
                    "success": False,
                    "message": "You cannot delete your own account"
                }, 400
            
            # Prevent deletion of essential system accounts
            protected_users = ['admin']
            if username_to_delete in protected_users:
                return {
                    "success": False,
                    "message": f"Cannot delete protected user({username_to_delete})"
                }, 403
            
            # Store user info for logging
            deleted_user_info = {
                "username": user_to_delete.username,
                "role": user_to_delete.role
            }
            
            # Delete associated OAuth tokens
            user_tokens = OAuth2Token.query.filter_by(user_id=user_to_delete.id).all()
            for token in user_tokens:
                db.session.delete(token)
            
            # Delete the user
            db.session.delete(user_to_delete)
            db.session.commit()
            

            # --- Logs Record --- #
            # Define the webapp if ip_addr is localhost
            if request.remote_addr == "127.0.0.1":
                current_ip = "127.0.0.1 (webapp)"
            else:
                current_ip = request.remote_addr

            # Log info
            level = "INFO"
            event_type = "DELETE_USER_SUCCESS"
            module = "auth"
            message = f"User({username_to_delete}) deleted successfully"
            ip_addr = current_ip
            method = "DELETE"
            endpoint = "/api/user/delete"
            details = {
                "deleted_by": current_username,
                "deleted_user": deleted_user_info,
                "tokens_removed": len(user_tokens)
            }
            
            syslog_create(level, event_type, module, message, current_username, ip_addr, method, endpoint, details)
            
            return {
                "success": True,
                "message": f"User({username_to_delete}) deleted successfully",
            }, 200
            
        except Exception as e:
            db.session.rollback()
            # --- Logs Record --- #
            # Define the webapp if ip_addr is localhost
            if request.remote_addr == "127.0.0.1":
                current_ip = "127.0.0.1 (webapp)"
            else:
                current_ip = request.remote_addr

            # Log info
            level = "ERROR"
            event_type = "DELETE_USER_SYS_ERROR"
            module = "auth"
            message = str(e)
            ip_addr = current_ip
            method = "DELETE"
            endpoint = "/api/user/delete"
            
            syslog_create(level, event_type, module, message, current_username, ip_addr, method, endpoint, None)
            
            return {
                "success": False,
                "message": f"{str(e)}"
            }, 500


# Get User Role Endpoint (Used for front-end)
class GetUserRole(Resource):
    @require_oauth()
    def get(self):
        """
        Get current user role based on token
        """
        try:
            # Get the OAuth token
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]


            # Get User ID
            token = OAuth2Token.query.filter_by(access_token=access_token).first()
            user_ID = token.user_id

            # Get user role
            user = User.query.filter_by(id=user_ID).first()
            userRole = user.role

            return {
                "success": True,
                "role": userRole
            }, 200
               
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }, 500


# Get User Name Endpoint (Used for front-end)
class GetUserName(Resource):
    @require_oauth()
    def get(self):
        """
        Get current username based on token
        """
        try:
            # Get the OAuth token & username
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            Username = get_username_with_token(access_token)

            # Return dictionary
            return {
                "success": True,
                "username": Username
            }, 200
             
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }, 500