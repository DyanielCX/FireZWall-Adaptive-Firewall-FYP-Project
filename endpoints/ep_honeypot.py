''' External Library Import '''
from flask_restful import Resource, reqparse
from datetime import datetime, timedelta
from flask import request
from sqlalchemy import and_
import ipaddress
import re


''' Internal File Import '''
from dbModel import HoneypotEvent
from source.auth import require_oauth
from source.syslog_record import syslog_create, get_username_with_token

class honeypot_report(Resource):
    @require_oauth()
    def get(self):
        
        parser = reqparse.RequestParser()
        parser.add_argument('event_type', type=str, required=False, choices=['brute-force attack', 'unauthorized access attemp'], help='Event type (brute-force attack/unauthorized access attemp)')
        parser.add_argument('ip', type=str, required=False, help='Source IP address')
        parser.add_argument('protocol', type=str, required=False, choices=['ssh', 'telnet'], help='Protocol (ssh/telnet)')
        parser.add_argument('timestamp', type=str, required=False, help='Timestamp(YYYY-MM-DD/YYYY-MM/YYYY)')

        args = parser.parse_args()
        query = HoneypotEvent.query

        # =============
        #   Filtering
        # =============

        ## Event type filtering ##
        event_type = args.get("event_type")

        if event_type:
            # Event type validation
            if event_type.lower() not in ['brute-force attack', 'unauthorized access attemp']:
                return {
                    "success": False,
                    "error": "Only enter brute-force attack/unauthorized access attemp for event type"
                }, 400

            query = query.filter_by(event_type=event_type)

        ## IP address filtering ##
        ip = args.get("ip")

        if ip:
            # IP address validation
            if (self._validate_ip_address(ip)):
                query = query.filter_by(src_ip=ip)
            else:
                return {
                    "success": False,
                    "error": "Invalid IP address"
                }, 400

        ## Protocol filtering ##
        protocol = args.get("protocol")

        if protocol:
            query = query.filter_by(protocol=protocol)

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
                    HoneypotEvent.timestamp >= t_start,
                    HoneypotEvent.timestamp <= t_end
                )
            )

        ## Pagination ##
        limit = int(args.get("limit", 50))
        offset = int(args.get("offset", 0))
        items = query.order_by(HoneypotEvent.id.desc()).offset(offset).limit(limit).all()
        
        results = [{
                    "id": e.id,
                    "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "eventid": e.event_id,
                    "event_type": e.event_type,
                    "src_ip": e.src_ip,
                    "protocol": e.protocol,
                    "username": e.username,
                    "password": e.password,
                    "duration": e.duration,
                    "tty_code": e.tty_code,
                    "message": e.message
                }for e in items]
        
        # # ---Logs Record--- #
        # # Get the OAuth token & username
        # auth_header = request.headers.get('Authorization')
        # access_token = auth_header.split(' ')[1]
        # Username = get_username_with_token(access_token)

        # # Log info
        # level = "INFO"
        # event_type = "VIEW_HONEYPOT_REPORT_SUCCESS"
        # module = "honeypot"
        # message = f"View the honeypot report succeed"
        # username = Username
        # ip_addr = request.remote_addr
        # method = "GET"
        # endpoint = "/api/honeypot/reports"
        # details = request.get_json()

        # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

        return {
            "success": True,
            "count": len(results),
            "reports": results
        }

    def _validate_ip_address(self,ip_str):
        """
        Validate an IPv4 address
        """
        if not ip_str or not isinstance(ip_str, str):
            return False
        
        # Basic format validation using regex
        ip_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(ip_pattern, ip_str)
        
        if not match:
            return False
        
        # Check each octet
        octets = match.groups()
        for i, octet in enumerate(octets):
            if len(octet) > 1 and octet.startswith('0'):
                return False
            
            # Check numeric range
            try:
                octet_value = int(octet)
                if not (0 <= octet_value <= 255):
                    return False
            except ValueError:
                return False
        
        # Check for reserved addresses
        try:
            ip = ipaddress.IPv4Address(ip_str)
            if ip.is_multicast:     # Valid IPv4 multicast address
                return False
            if ip.is_private:       # Valid IPv4 private address
                return True
            if ip.is_loopback:      # Valid IPv4 loopback address
                return True
            if ip.is_link_local:    # Valid IPv4 link-local address
                return True
            if ip.is_unspecified:   # Unspecified address (0.0.0.0) is not valid
                return False
        except Exception as e:
            return False
        
        return True
    
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