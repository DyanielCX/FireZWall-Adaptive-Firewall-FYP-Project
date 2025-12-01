''' External Library Import '''
from flask_restful import Resource, reqparse
from flask import request


''' Internal File Import '''
from dbModel import db, ServicerPort
from source.auth import require_oauth_with_scope
from source.syslog_record import syslog_create, get_username_with_token

# Common Service Port Endpoint
class CommonServicePort(Resource):

    #===== View Common Service Port =====#
    @require_oauth_with_scope('admin') # Admin access only
    def get(self):
        """
        Get the common port list
        """
        query = ServicerPort.query
        
        results = [{
                    "service": e.service,
                    "port": e.port
                }for e in query]
        
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
        event_type = "VIEW_COMMON_SERVICE_PORT_SUCCESS"
        module = "firewall"
        message = f"View the common service port succeed"
        username = Username
        ip_addr = current_ip
        method = "GET"
        endpoint = "/api/firewall/svc-port"
        details = request.get_json()

        syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

        return {
            "success": True,
            "count": len(results),
            "service ports": results
        }
    
    #===== Add Common Service Port Endpoint =====#
    @require_oauth_with_scope('admin')
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('service', type=str, required=True, help='Service')
        parser.add_argument('port', type=str, required=True, help='Port Number')
        
        args = parser.parse_args()
        inp_service = args['service'].lower()
        inp_port = args['port']
        
        # Validate service cannot be numeric
        if inp_service.isdigit():
            return {
                'valid': False,
                'error': 'Service cannot a numeric value'
            }, 400
        
        # Validate port is integer
        if not inp_port.isdigit():
            return {
                'valid': False,
                'error': 'Port must be a numeric value'
            }, 400

        # Check if service already exists
        if ServicerPort.query.filter_by(service=inp_service).first():
            return {
                "success": False,
                'error': 'Service already exists'
            }, 400
        
        # Add new common service port
        newServicerPort = ServicerPort(
            service = inp_service.lower(),
            port = inp_port
        )
        
        try:
            db.session.add(newServicerPort)
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
            event_type = "COMMON_SERVICE_PORT_ADDED_SUCCESS"
            module = "firewall"
            message = f"Service({inp_service}) with port {inp_port} is added succeed"
            username = Username
            ip_addr = current_ip
            method = "POST"
            endpoint = "/api/firewall/svc-port"
            details = request.get_json()

            syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

            return {
                "success": True,
                'message': f"Service({inp_service}) with port {inp_port} is added succeed"
            }, 201
        except Exception as e:
            db.session.rollback()
            return {
                "success": False,
                'error': str(e)
            }, 500


    #===== Delete Common Service Port Endpoint =====#
    @require_oauth_with_scope('admin')
    def delete(self):
        
        parser = reqparse.RequestParser()
        parser.add_argument('service', type=str, required=False, help='Service')
        parser.add_argument('port', type=str, required=False, help='Port Number')

        args = parser.parse_args()
        query = ServicerPort.query

        # Validate that at least one of port or service is provided
        if not args['port'] and not args['service']:
            return {
                "success": False,
                "error": "Either port or service must be provided"
            }, 400

        try:
            # Get the OAuth token & username (Admin acc)
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            Username = get_username_with_token(access_token)

            # ==========================
            #   Filtering & Validation
            # ==========================

            # Service Filtering & Validation
            inp_service = args['service']
            inp_port = args['port']
            
            # If service provide
            if inp_service:
                service_to_delete = query.filter_by(service=inp_service).first()
                # Not existed service
                if not service_to_delete:
                    return {
                        "success": False,
                        "message": f"Service({inp_service}) does not exist"
                    }, 404

                # Not matching port (service + port provided)
                if inp_port:
                    if service_to_delete.port != inp_port:
                        return {
                        "success": False,
                        "message": f"Provided port is not matched with service ({inp_service})"
                    }, 404
                
                # Delete the selected service
                db.session.delete(service_to_delete)
                db.session.commit()

                # --- Logs Record --- #
                # Define the webapp if ip_addr is localhost
                if request.remote_addr == "127.0.0.1":
                    current_ip = "127.0.0.1 (webapp)"
                else:
                    current_ip = request.remote_addr

                # Log info
                level = "INFO"
                event_type = "DELETE_COMMON_SERVICE_PORT_SUCCESS"
                module = "auth"
                message = f"Service({service_to_delete.service}) with port {service_to_delete.port} is deleted successfully"
                ip_addr = current_ip
                method = "DELETE"
                endpoint = "/api/firewall/svc-port"
                details = request.get_json()
                
                syslog_create(level, event_type, module, message, Username, ip_addr, method, endpoint, details)
                
                return {
                    "success": True,
                    "message": f"Service({service_to_delete.service}) with port {service_to_delete.port} is deleted successfully",
                }, 200

            # If only port provided
            if inp_port:
                service_to_delete = query.filter_by(port=inp_port).first()
                # Not existed port
                if not service_to_delete:
                    return {
                        "success": False,
                        "message": f"Service with port {inp_port} does not exist"
                    }, 404
                
                # Delete the selected service
                db.session.delete(service_to_delete)
                db.session.commit()

                # --- Logs Record --- #
                # Define the webapp if ip_addr is localhost
                if request.remote_addr == "127.0.0.1":
                    current_ip = "127.0.0.1 (webapp)"
                else:
                    current_ip = request.remote_addr

                # Log info
                level = "INFO"
                event_type = "DELETE_COMMON_SERVICE_PORT_SUCCESS"
                module = "auth"
                message = f"Service({service_to_delete.service}) with port {service_to_delete.port} is deleted successfully"
                ip_addr = current_ip
                method = "DELETE"
                endpoint = "/api/firewall/svc-port"
                details = request.get_json()
                
                syslog_create(level, event_type, module, message, Username, ip_addr, method, endpoint, details)
                
                return {
                    "success": True,
                    "message": f"Service({service_to_delete.service}) with port {service_to_delete.port} is deleted successfully",
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
            event_type = "DELETE_COMMON_SERVICE_PORT_SYS_ERROR"
            module = "firewall"
            message = str(e)
            ip_addr = current_ip
            method = "DELETE"
            endpoint = "/api/firewall/svc-port"
            
            syslog_create(level, event_type, module, message, Username, ip_addr, method, endpoint, None)
            
            return {
                "success": False,
                "message": f"{str(e)}"
            }, 500