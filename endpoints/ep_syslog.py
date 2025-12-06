''' External Library Import '''
from flask_restful import Resource, reqparse
from datetime import datetime, timedelta
from flask import request
from sqlalchemy import and_
import ipaddress
import re


''' Internal File Import '''
from config import app
from dbModel import User, SystemLog
from source.auth import require_oauth
from source.syslog_record import syslog_create, get_username_with_token

class ViewSyslog(Resource):
    @require_oauth()
    def post(self):
        
        parser = reqparse.RequestParser()
        parser.add_argument('timestamp', type=str, required=False, help='Timestamp (YYYY-MM-DD/YYYY-MM/YYYY)')
        parser.add_argument('level', type=str, required=False, help='Level (info/warning/error)')
        parser.add_argument('module', type=str, required=False, help='Module (auth/firewall/honeypot/syslog)')
        parser.add_argument('username', type=str, required=False, help='Username (Action User)')
        parser.add_argument('endpoint', type=str, required=False, help='Endpoint (/api/xxx/xxx)')

        args = parser.parse_args()
        query = SystemLog.query

        # Get the OAuth token, current username & role
        auth_header = request.headers.get('Authorization')
        access_token = auth_header.split(' ')[1]
        current_username = get_username_with_token(access_token)
        current_user = User.query.filter_by(username = current_username).first()
        current_user_role = current_user.role

        # =============
        #   Filtering
        # =============

        ## Timestamp filtering ##
        timestamp = args.get("timestamp")

        if timestamp:
            t_start, t_end = self._parse_time_input(timestamp)
            if not t_start:
                return {
                    "success": False, 
                    "error": "Invalid timestamp. Timestamp format: (YYYY-MM-DD/YYYY-MM/YYYY)"
                    }, 400

            query = query.filter(
                and_(
                    SystemLog.timestamp >= t_start,
                    SystemLog.timestamp <= t_end
                )
            )
        
        ## Level filtering ##
        level = args.get("level")

        if level:
            # Level type validation
            if level.upper() not in ['INFO', 'WARNING', 'ERROR']:
                return {
                    "success": False,
                    "error": "Only enter info/warning/error for level"
                }, 400

            query = query.filter_by(level=level.upper())

        ## Module address filtering ##
        module = args.get("module")

        if module:
            # Module type validation
            if module not in ['auth', 'firewall', 'honeypot', 'syslog']:
                return {
                    "success": False,
                    "error": "Only enter auth/firewall/honeypot/syslog for module"
                }, 400
            query = query.filter_by(module=module)

        ## Username filtering ##
        username = args.get("username")

        if username:
            
            if current_user_role != 'admin':
                return {
                    "success": False,
                    "error": f"Only admin can filter username"
                }, 400

            # Check user either exist
            username_check = User.query.filter_by(username=username).first()

            if not username_check:
                return {
                    "success": False,
                    "error": f"Username ({username}) not found"
                }, 400

            # Check logs with username either exist
            query = query.filter_by(username=username)
            record = query.first()

            if record is None:
                return {
                    "success": False,
                    "error": f"Result with username({username}) not found"
                }, 400
            
        ## Endpoint filtering ##
        endpoint = args.get("endpoint")

        if endpoint:
            # Check endpoint either exist
            endpoint_list = [
                rule.rule for rule in app.url_map.iter_rules()
                if rule.rule.startswith("/api")
            ]

            if endpoint not in endpoint_list:
                return {
                    "success": False,
                    "error": f"Endpoint({endpoint}) not found"
                }, 400

            query = query.filter_by(endpoint=endpoint)

        ## Role-based filtering (not admin user only view own log) ##
        if current_user_role != 'admin':
            query = query.filter_by(username=current_username)
        
        results = [{
                    "id": e.id,
                    "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "level": e.level,
                    "event_type": e.event_type,
                    "module": e.module,
                    "message": e.message,
                    "username": e.username,
                    "ip_addr": e.ip_addr,
                    "method": e.method,
                    "endpoint": e.endpoint,
                    "details": e.details
                }for e in query]
        
        # --- Logs Record --- #
        # Define the webapp if ip_addr is localhost
        if request.remote_addr == "127.0.0.1":
            current_ip = "127.0.0.1 (webapp)"
        else:
            current_ip = request.remote_addr

        # Log info
        level = "INFO"
        event_type = "VIEW_SYSLOGS_SUCCESS"
        module = "syslog"
        message = f"View the system logs succeed"
        username = current_username
        ip_addr = current_ip
        method = "GET"
        endpoint = "/api/logs"
        details = request.get_json()

        syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

        return {
            "success": True,
            "count": len(results),
            "logs": results
        }

    
    def _parse_time_input(self, value):
        """
        Return (start_datetime, end_datetime) or (None, None) if invalid.
        """
        try:
            parts = value.split("-")

            # 1. Year only: YYYY
            if len(parts) == 1:
                year = int(parts[0])
                start = datetime(year, 1, 1)
                end = datetime(year, 12, 31, 23, 59, 59)
                return start, end

            # 2. Year-month: YYYY-MM
            if len(parts) == 2:
                year = int(parts[0])
                month = int(parts[1])
                start = datetime(year, month, 1)
                # calculate end of month
                if month == 12:
                    end = datetime(year, 12, 31, 23, 59, 59)
                else:
                    end = datetime(year, month + 1, 1) - timedelta(seconds=1)
                return start, end

            # 3. Full date: YYYY-MM-DD
            if len(parts) == 3:
                year = int(parts[0])
                month = int(parts[1])
                day = int(parts[2])
                start = datetime(year, month, day)
                end = datetime(year, month, day, 23, 59, 59)
                return start, end

            return None, None

        except Exception:
            return None, None