''' External Library Import '''
from flask import request, jsonify
from flask_restful import Resource, reqparse
import subprocess
import ipaddress
import re

''' Internal File Import '''
from source.auth import require_oauth
from source.syslog_record import syslog_create, get_username_with_token

# Protected Firewall Endpoint
class Firewall(Resource):

    ## Post Request
    @require_oauth()  # Requires valid OAuth token
    def post(self):
        """
        Add firewall rule by port/service
        """
        parser = reqparse.RequestParser()
        parser.add_argument('action', type=str, required=False, default='allow', help='Action (allow/deny/reject)')
        parser.add_argument('port', type=str, required=False, help='Port number (optional if service is provided)')
        parser.add_argument('service', type=str, required=False, help='Service name (optional if port is provided)')
        parser.add_argument('protocol', type=str, required=False, default='tcp', choices=['tcp', 'udp'], help='Protocol (tcp/udp)')
        parser.add_argument('direction', type=str, required=False, choices=['in', 'out'], help='Direction (in/out)')
        parser.add_argument('ipv4', type=str, required=False, default='true', help='Apply to IPv4 rules (true/false)')
        parser.add_argument('ipv6', type=str, required=False, default='true', help='Apply to IPv6 rules (true/false)')
        parser.add_argument('source', type=str, required=False, help='Source (IP address/CIDR Subnet)')
        
        args = parser.parse_args()
        
        # Input Cleaning & Validation #
        # Standard & validate action input
        action = args['action'].lower()

        if action not in ['allow', 'deny', 'reject']:
            return {
                "success": False,
                "error": "Only enter allow/deny/reject for action"
            }, 400
        
        # Validate that at least one of port or service is provided
        if not args['port'] and not args['service']:
            return {
                "success": False,
                "error": "Either port or service must be provided"
            }, 400
        
        # If service is provided, get the port number for that service
        target_port = args['port']
        if args['service']:
            target_port = self._service_to_port(args['service'])
            if not target_port:
                return {
                    "success": False,
                    "error": f"Service '{args['service']}' not found or has no default port"
                }, 400

        # Standard & validate ipv4 ipv6 input
        ipv4 = args['ipv4'].lower()
        ipv6 = args['ipv6'].lower()
        protocol = args['protocol']

        if ipv4 not in ['true', 'false'] or ipv6 not in ['true', 'false']:
            return {
                "success": False,
                "error": "Only enter true/false for ipv4 & ipv6"
            }, 400
        
        if ipv4 == "false" and ipv6 == "false":
            return {
                "success": False,
                "error": "Please enter at least a true for ipv4 & ipv6"
            }, 400
        
        # Convert string booleans to actual booleans
        if isinstance(ipv4, str):
            ipv4 = ipv4.lower() in ['true', '1', 'yes', 'y']
        if isinstance(ipv6, str):
            ipv6 = ipv6.lower() in ['true', '1', 'yes', 'y']
        
        ipv4 = bool(ipv4)
        ipv6 = bool(ipv6)

        # Define add rule condition #
        # State the condition flags
        default_rule = False
        with_direction_rule = False
        with_source_ip_rule = False
        with_direction_source_ip_rule = False

        # Determine rule condition with source validation
        if not args['direction'] and not args['source']:
            default_rule = True

        elif args['direction'] and not args['source']:
            direction = args['direction']
            with_direction_rule = True

        elif not args['direction'] and args['source']:
            validation, msg = self._validate_ip_or_cidr(args['source'])
            
            if validation:
                source = args['source']
                with_source_ip_rule = True
            else:
                return {
                "success": False,
                "error": msg
            }, 400

        elif args['direction'] and args['source']:
            direction = args['direction']
            source = args['source']
            validation, msg = self._validate_ip_or_cidr(args['source'])
            
            if validation:
                with_direction_source_ip_rule = True
            else:
                return {
                "success": False,
                "error": msg
            }, 400
            

        # Debug Logging
        # print(f"default_rule: {default_rule}")
        # print(f"with_direction_rule: {with_direction_rule}")
        # print(f"with_source_ip_rule: {with_source_ip_rule}")
        # print(f"with_direction_source_ip_rule: {with_direction_source_ip_rule}")
        # return jsonify({"success": True})

        # ---Add the firewall rules based on condition--- #
        try:
            if default_rule:
                # Build and run the ufw command
                cmd = ["sudo", "/usr/sbin/ufw", action, f"{target_port}/{protocol}"]
                subprocess.run(cmd, capture_output=True, text=True)

                # Remove ipv4/ipv6 rule if one of them is false
                if (not ipv4 and ipv6) or (not ipv6 and ipv4):
                    current_rules = self._get_current_rules()
                    matching_rules = self._find_matching_rules(
                        current_rules, 
                        args['action'], 
                        target_port, 
                        args['protocol'], 
                        not(ipv4), 
                        not(ipv6)
                    )
                    self._delete_rules(matching_rules)
                
                # # ---Logs Record--- #
                # # Get the OAuth token & username
                # auth_header = request.headers.get('Authorization')
                # access_token = auth_header.split(' ')[1]
                # Username = get_username_with_token(access_token)

                # # Log info
                # level = "INFO"
                # event_type = "ADD_FIREWALL_RULE_SUCCESS"
                # module = "firewall"
                # message = f"Rule - {action} port {target_port}/{protocol} with (IPv4:{ipv4} IPv6:{ipv6}) is added successfully"
                # username = Username
                # ip_addr = request.remote_addr
                # method = "POST"
                # endpoint = "/api/firewall"
                # details = request.get_json()

                # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)

                return jsonify({
                    "success": True,
                    "message": f"Rule - {action} port {target_port}/{protocol} with (IPv4:{ipv4} IPv6:{ipv6}) is added successfully"
                })
            
            elif with_direction_rule:
                # Build and run the ufw command
                cmd = ["sudo", "/usr/sbin/ufw", action, direction, f"{target_port}/{protocol}"]
                subprocess.run(cmd, capture_output=True, text=True)

                # Remove ipv4/ipv6 rule if one of them is false
                if (not ipv4 and ipv6) or (not ipv6 and ipv4):
                    current_rules = self._get_current_rules()
                    matching_rules = self._find_matching_rules(
                        current_rules, 
                        args['action'], 
                        target_port, 
                        args['protocol'], 
                        not(ipv4), 
                        not(ipv6)
                    )
                    self._delete_rules(matching_rules)

                # # ---Logs Record--- #
                # # Get the OAuth token & username
                # auth_header = request.headers.get('Authorization')
                # access_token = auth_header.split(' ')[1]
                # Username = get_username_with_token(access_token)

                # # Log info
                # level = "INFO"
                # event_type = "ADD_FIREWALL_RULE_SUCCESS"
                # module = "firewall"
                # message = f"Rule - {action} {direction} to port {target_port}/{protocol} with (IPv4:{ipv4} IPv6:{ipv6}) is added successfully"
                # username = Username
                # ip_addr = request.remote_addr
                # method = "POST"
                # endpoint = "/api/firewall"
                # details = request.get_json()

                # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
                
                return jsonify({
                    "success": True,
                    "message": f"Rule - {action} {direction} to port {target_port}/{protocol} with (IPv4:{ipv4} IPv6:{ipv6}) is added successfully"
                })
            
            elif with_source_ip_rule:
                # Build and run the ufw command
                cmd = ["sudo", "/usr/sbin/ufw", action, "from", source, "to", "any", "port", target_port, "proto", protocol]
                subprocess.run(cmd, capture_output=True, text=True)

                # # ---Logs Record--- #
                # # Get the OAuth token & username
                # auth_header = request.headers.get('Authorization')
                # access_token = auth_header.split(' ')[1]
                # Username = get_username_with_token(access_token)

                # # Log info
                # level = "INFO"
                # event_type = "ADD_FIREWALL_RULE_SUCCESS"
                # module = "firewall"
                # message = f"Rule - {action} from {source} to port {target_port}/{protocol} is added successfully"
                # username = Username
                # ip_addr = request.remote_addr
                # method = "POST"
                # endpoint = "/api/firewall"
                # details = request.get_json()

                # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
                
                return jsonify({
                    "success": True,
                    "message": f"Rule - {action} from {source} to port {target_port}/{protocol} is added successfully"
                })
            
            elif with_direction_source_ip_rule:
                # Build and run the ufw command
                cmd = ["sudo", "/usr/sbin/ufw", action, direction, "from", source, "to", "any", "port", target_port, "proto", protocol]
                subprocess.run(cmd, capture_output=True, text=True)

                # # ---Logs Record--- #
                # # Get the OAuth token & username
                # auth_header = request.headers.get('Authorization')
                # access_token = auth_header.split(' ')[1]
                # Username = get_username_with_token(access_token)

                # # Log info
                # level = "INFO"
                # event_type = "ADD_FIREWALL_RULE_SUCCESS"
                # module = "firewall"
                # message = f"Rule - {action} {direction} from {source} to port {target_port}/{protocol} is added successfully"
                # username = Username
                # ip_addr = request.remote_addr
                # method = "POST"
                # endpoint = "/api/firewall"
                # details = request.get_json()

                # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
                
                return jsonify({
                    "success": True,
                    "message": f"Rule - {action} {direction} from {source} to port {target_port}/{protocol} is added successfully"
                })

        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500



    ## Delete Request
    @require_oauth()
    def delete(self):
        """
        Delete firewall rule by port/service
        """
        parser = reqparse.RequestParser()
        parser.add_argument('action', type=str, required=False, default='allow', help='Action (allow/deny/reject)')
        parser.add_argument('port', type=str, required=False, help='Port number (optional if service is provided)')
        parser.add_argument('service', type=str, required=False, help='Service name (optional if port is provided)')
        parser.add_argument('protocol', type=str, required=False, default='tcp', choices=['tcp', 'udp', 'any'], help='Protocol (tcp/udp/any)')
        parser.add_argument('ipv4', type=str, required=False, default='true', help='Apply to IPv4 rules (true/false)')
        parser.add_argument('ipv6', type=str, required=False, default='true', help='Apply to IPv6 rules (true/false)')
        
        args = parser.parse_args()
        
        # Input Cleaning & Validation #
        # Validate that at least one of port or service is provided
        if not args['port'] and not args['service']:
            return {
                "success": False,
                "error": "Either port or service must be provided"
            }, 400

        # Standard & validate ipv4 ipv6 input
        ipv4 = args['ipv4'].lower()
        ipv6 = args['ipv6'].lower()
        protocol = args['protocol'].upper()

        if ipv4 not in ['true', 'false'] or ipv6 not in ['true', 'false']:
            return {
                "success": False,
                "error": "Only enter true/false for ipv4 & ipv6"
            }, 400

        if ipv4 == "false" and ipv6 == "false":
            return {
                "success": False,
                "error": "Please enter at least a true for ipv4 & ipv6"
            }, 400
        
        # Convert string booleans to actual booleans
        if isinstance(ipv4, str):
            ipv4 = ipv4.lower() in ['true', '1', 'yes', 'y']
        if isinstance(ipv6, str):
            ipv6 = ipv6.lower() in ['true', '1', 'yes', 'y']
        
        ipv4 = bool(ipv4)
        ipv6 = bool(ipv6)

        try:
            # If service is provided, get the port number for that service
            target_port = args['port']
            if args['service']:
                target_port = self._service_to_port(args['service'])
                if not target_port:
                    return {
                        "success": False,
                        "error": f"Service '{args['service']}' not found or has no default port"
                    }, 400
            
            # Get current firewall rules
            current_rules = self._get_current_rules()
            
            # Debug Logging
            # print("=== DEBUG INFO ===")
            # print(f"Target port: {target_port}")
            # print(f"Protocol: {args['protocol']}")
            # print(f"IPv4: {ipv4} (type: {type(ipv4)})")
            # print(f"IPv6: {ipv6} (type: {type(ipv6)})")
            # print(f"Total rules: {len(current_rules)}")
            
            # Find rules that match the criteria
            matching_rules = self._find_matching_rules(
                current_rules, 
                args['action'], 
                target_port, 
                args['protocol'], 
                ipv4, 
                ipv6
            )
            
            # Debug Logging
            # print(f"Matching rules found: {len(matching_rules)}")
            # for rule in matching_rules:
            #     print(f"  - Rule {rule['rule_number']}: {rule['port']}/{rule['protocol']} IPv4:{rule['ipv4']} IPv6:{rule['ipv6']}")
            
            if not matching_rules:
                return {
                    "success": False,
                    "error": f"No matching rules found for {args['action']} port {target_port}/{args['protocol']} with IPv4:{not(ipv4)} IPv6:{not(ipv6)}"
                }, 404
            
            # Delete the matching rules
            deletion_results = self._delete_rules(matching_rules)

            # Calculate common details for the response
            details = self._get_deletion_details(matching_rules, target_port, protocol, args['service'])
            

            # # ---Logs Record--- #
            # # Get the OAuth token & username
            # auth_header = request.headers.get('Authorization')
            # access_token = auth_header.split(' ')[1]
            # Username = get_username_with_token(access_token)

            # # Log info
            # level = "INFO"
            # event_type = "DELETE_FIREWALL_RULE_SUCCESS"
            # module = "firewall"
            # message = f"Successfully deleted {len(deletion_results)} rule(s) for port {target_port}/{args['protocol']}"
            # username = Username
            # ip_addr = request.remote_addr
            # method = "DELETE"
            # endpoint = "/api/firewall"
            # details = request.get_json()

            # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, details)
            
            return {
                "success": True,
                "message": f"Successfully deleted {len(deletion_results)} rule(s) for port {target_port}/{args['protocol']}",
                "deleted_rules": deletion_results,
                "details": details
            }, 200
            
        except Exception as e:
            # # ---Logs Record--- #
            # # Get the OAuth token & username
            # auth_header = request.headers.get('Authorization')
            # access_token = auth_header.split(' ')[1]
            # Username = get_username_with_token(access_token)

            # # Log info
            # level = "ERROR"
            # event_type = "EP_FIREWALL_DELETE_SYS_ERROR"
            # module = "firewall"
            # message = str(e)
            # username = Username
            # ip_addr = request.remote_addr
            # method = "DELETE"
            # endpoint = "/api/firewall"

            # syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, None)

            return {
                "success": False,
                "error": str(e)
            }, 500
    
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
    
    def _validate_ipv6_address(self, ipv6_str):
        """
        Validate an IPv6 address
        """
        if not ipv6_str or not isinstance(ipv6_str, str):
            return False
        
        # Remove any surrounding whitespace
        ipv6_str = ipv6_str.strip()
        
        try:
            ip = ipaddress.IPv6Address(ipv6_str)
            
            # Additional information about the IPv6 address
            if ip.is_multicast:     # Valid IPv6 multicast address
                return True
            if ip.is_private:       # Valid IPv6 unique local address (ULA)
                return True
            if ip.is_loopback:      # Valid IPv6 loopback address
                return True
            if ip.is_link_local:    # Valid IPv6 link-local address
                return True
            if ip.is_unspecified:   # Valid IPv6 unspecified address (::)
                return True
            if ip.is_reserved:      # Valid IPv6 reserved address
                return True
                
            return True
            
        except ipaddress.AddressValueError as e:
            return False
        except Exception as e:
            return False
    

    def _validate_cidr_subnet(self, cidr_str):
        """
        Validate a CIDR subnet notation
        """
        if not cidr_str or not isinstance(cidr_str, str):
            return False
        
        # Check for CIDR format with slash
        if '/' not in cidr_str:
            return False
        
        parts = cidr_str.split('/')
        if len(parts) != 2:
            return False
        
        ip_part, mask_part = parts
        
        # Validate IP part
        is_valid_ip = self._validate_ip_address(ip_part)
        if not is_valid_ip:
            return False
        
        # Validate subnet mask
        try:
            mask_value = int(mask_part)
            if not (0 <= mask_value <= 32):
                return False
        except ValueError:
            return False
        
        # Validate the complete CIDR using ipaddress module
        try:
            network = ipaddress.IPv4Network(cidr_str, strict=False)
            
            if network.num_addresses == 0:
                return False
                
            return True
            
        except ValueError as e:
            return False
        except Exception as e:
            return False
        
    def _validate_ipv6_cidr_subnet(self, ipv6_cidr_str):
        """
        Validate an IPv6 CIDR subnet notation
        """
        if not ipv6_cidr_str or not isinstance(ipv6_cidr_str, str):
            return False
        
        # Check for CIDR format with slash
        if '/' not in ipv6_cidr_str:
            return False
        
        parts = ipv6_cidr_str.split('/')
        if len(parts) != 2:
            return False
        
        ip_part, prefix_part = parts
        
        # Validate IPv6 address part
        is_valid_ipv6 = self._validate_ipv6_address(ip_part)
        if not is_valid_ipv6:
            return False
        
        # Validate prefix length
        try:
            prefix_value = int(prefix_part)
            if not (0 <= prefix_value <= 128):
                return False
        except ValueError:
            return False
        
        # Validate the complete IPv6 CIDR using ipaddress module
        try:
            network = ipaddress.IPv6Network(ipv6_cidr_str, strict=False)
            
            # Additional validations
            if network.num_addresses == 0:
                return False
                
            return True
            
        except ValueError as e:
            return False
        except Exception as e:
            return False

    def _validate_ip_or_cidr(self,input_str):
        """
        Validate either an IP address or CIDR subnet
        Returns: (is_valid, type)
        """

        # Check if it's CIDR notation (contains slash)
        if '/' in input_str:
            # Try IPv4 first, then IPv6
            is_valid_v4= self._validate_cidr_subnet(input_str)
            if is_valid_v4:
                return True, "IPv4 CIDR subnet"
            
            is_valid_v6= self._validate_ipv6_cidr_subnet(input_str)
            if is_valid_v6:
                return True, "IPv4 CIDR subnet"
            
            return False, "Invalid IPv4/IPv6 CIDR subnet is provided"
        else:
            # Try IPv4 first, then IPv6
            is_valid_v4 = self._validate_ip_address(input_str)
            if is_valid_v4:
                return True, "IPv4 address"
            
            is_valid_v6 = self._validate_ipv6_address(input_str)
            if is_valid_v6:
                return True, "IPv6 address"
            
            return False, "Invalid IPv4/IPv6 address is provided"
        

    def _service_to_port(self, service_name):
        """
        Convert service name to default port number
        """
        service_ports = {
            'http': '80',
            'https': '443',
            'ftp': '21',
            'smtp': '25',
            'dns': '53',
            'dhcp': '67',
            'ntp': '123',
            'imap': '143',
            'pop3': '110',
            'mysql': '3306',
            'postgresql': '5432',
            'redis': '6379',
            'mongodb': '27017',
            'elasticsearch': '9200',
            'kibana': '5601',
            'grafana': '3000',
            'prometheus': '9090'
        }
        
        # Convert to lowercase for case-insensitive matching
        service_lower = service_name.lower()
        return service_ports.get(service_lower)
    
    def _get_current_rules(self):
        """
        Get current firewall rules with rule numbers
        """
        try:
            cmd = ["sudo", "ufw", "status", "numbered"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Failed to get firewall status: {result.stderr}")
            
            return self._parse_rules_with_numbers(result.stdout)
            
        except Exception as e:
            raise Exception(f"Error getting current rules: {str(e)}")
    
    def _parse_rules_with_numbers(self, output):
        """
        Parse UFW rules including their rule numbers
        """
        rules = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and header lines
            if (not line or 
                'Status:' in line or 
                ('To' in line and 'Action' in line and 'From' in line)):
                continue
            
            # Parse rule lines (they start with [number])
            if line.startswith('[') and ']' in line:
                rule = self._parse_rule_with_number(line)
                if rule:
                    rules.append(rule)
        
        return rules
    
    def _parse_rule_with_number(self, line):
        """
        Parse a single UFW rule line including rule number
        """
        try:
            # Extract rule number
            start_bracket = line.find('[')
            end_bracket = line.find(']')
            rule_number = line[start_bracket + 1:end_bracket].strip()
            
            # Extract rule details
            rule_text = line[end_bracket + 1:].strip()
            
            # Split by multiple spaces
            parts = [p.strip() for p in rule_text.split('  ') if p.strip()]
            
            if len(parts) < 3:
                return None
            
            port_info, action_info, source_info = parts[0], parts[1], parts[2]
            
            # Parse components
            port, protocol = self._parse_port_protocol(port_info)
            action, direction = self._parse_action_direction(action_info)
            source, ipv4, ipv6 = self._parse_ip_version(port_info, source_info)
            
            return {
                "rule_number": rule_number,
                "action": action,
                "port": port,
                "protocol": protocol,
                "direction": direction,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "source": source,
                "original_line": line
            }
            
        except Exception as e:
            return None
    
    def _find_matching_rules(self, rules, action, target_port, protocol, ipv4, ipv6):
        """
        Find rules that match the specified criteria
        """
        matching_rules = []
        
        # Debug Logging
        # print(f"=== MATCHING CRITERIA ===")
        # print(f"Looking for: port={target_port}, protocol={protocol}")
        # print(f"Delete param: ipv4={ipv4}, ipv6={ipv6}")
        
        for rule in rules:
            # print(f"\nChecking rule {rule['rule_number']}: {rule['action']} {rule['port']}/{rule['protocol']} IPv4:{rule['ipv4']} IPv6:{rule['ipv6']}")
            
            # Check if rule matches the action
            action = action.upper()
            if rule['action'] != action:
                # print(f"  - Action mismatch: {rule['action']} != {action}")
                continue

            # Check if rule matches the port
            if rule['port'] != target_port:
                # print(f"  - Port mismatch: {rule['port']} != {target_port}")
                continue
            
            # Check if rule matches the protocol (case insensitive)
            rule_protocol = rule['protocol'].lower()
            target_protocol = protocol.lower()

            if rule_protocol != target_protocol and rule_protocol != 'any':
                # print(f"  - Protocol mismatch: {rule_protocol} != {target_protocol}")
                continue

           # Check IP version - THE KEY LOGIC
            ipv4_ok = ipv4 and rule['ipv4']
            ipv6_ok = ipv6 and rule['ipv6']
            
            if not (ipv4_ok or ipv6_ok):
                continue
            
            # print(f"  - Rule MATCHED!")
            matching_rules.append(rule)
        
        return matching_rules
    
    def _delete_rules(self, rules):
        """
        Delete the specified rules by their rule numbers
        """
        deletion_results = []
        
        # Sort rules by rule number in descending order to avoid renumbering issues
        rules.sort(key=lambda x: int(x['rule_number']), reverse=True)
        
        for rule in rules:
            try:
                # Delete the rule by number
                cmd = ["sudo", "ufw", "--force", "delete", rule['rule_number']]
                result = subprocess.run(cmd, capture_output=True, text=True, input='y\n')
                
                success = result.returncode == 0
                
                deletion_results.append({
                    "action": rule['action'],
                    "port": rule['port'],
                    "protocol": rule['protocol'],
                    "direction": rule['direction'],
                    "ipv4": rule['ipv4'],
                    "ipv6": rule['ipv6'],
                    "source": rule['source'],
                    "success": success,
                })
                    
            except Exception as e:
                deletion_results.append({
                    "rule_number": rule['rule_number'],
                    "action": rule['action'],
                    "port": rule['port'],
                    "protocol": rule['protocol'],
                    "direction": rule['direction'],
                    "ipv4": rule['ipv4'],
                    "ipv6": rule['ipv6'],
                    "source": rule['source'],
                    "success": False,
                    "error": str(e) 
                })
        
        return deletion_results
    
    def _get_deletion_details(self, matching_rules, target_port, protocol, service):
        """
        Extract common details from the deleted rules for the response
        """
        if not matching_rules:
            return {}
        
        # Get the most common action, direction, and source
        actions = [rule['action'] for rule in matching_rules]
        directions = [rule['direction'] for rule in matching_rules]
        sources = [rule['source'] for rule in matching_rules]
        
        # Use the most frequent value, or the first if all are equally frequent
        from collections import Counter
        
        common_action = Counter(actions).most_common(1)[0][0] if actions else 'ALLOW'
        common_direction = Counter(directions).most_common(1)[0][0] if directions else 'IN'
        common_source = Counter(sources).most_common(1)[0][0] if sources else 'Anywhere'
        
        return {
            "action": common_action,
            "port": target_port,
            "protocol": protocol.upper(),
            "direction": common_direction,
            "source": common_source,
            "service": service.lower() if service else None
        }
    
    def _parse_port_protocol(self, port_info):
        """
        Parse port and protocol
        """
        clean = re.sub(r'\s*\(v6\)\s*', '', port_info)
        if '/' in clean:
            port, protocol = clean.split('/')
            return port.strip(), protocol.strip().upper()
        return clean.strip(), "any"
    
    def _parse_action_direction(self, action_info):
        """
        Parse action and direction
        """
        parts = action_info.split()
        action = parts[0] if parts else "UNKNOWN"
        direction = parts[1] if len(parts) > 1 else "IN"
        return action.upper(), direction.upper()
    
    def _parse_ip_version(self, port_info, source_info):
        """
        Determine IP version and clean source
        """
        # Clean the source
        clean_source = re.sub(r'\s*\(v6\)\s*', '', source_info).strip()
        clean_source = re.sub(r'\s*\(out\)\s*', '', clean_source).strip()
        
        # Check for explicit IPv6 keyword
        if '(v6)' in port_info or '(v6)' in source_info:
            return clean_source, False, True
        
        # IPv6 addr validate: if it contains a colon, it's IPv6
        has_colon = ':' in clean_source
        
        # Common non-IP values that might contain colons (edge cases)
        non_ip_with_colons = ['Anywhere', 'anywhere', 'ANYWHERE', 'any', 'ANY']
        
        if has_colon and clean_source not in non_ip_with_colons:
            return clean_source, False, True
        else:
            return clean_source, True, False