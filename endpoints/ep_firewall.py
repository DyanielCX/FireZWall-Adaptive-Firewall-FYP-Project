''' External Library Import '''
from flask import request, jsonify
from flask_restful import Resource, reqparse
import subprocess
import re

''' Internal File Import '''
from dbModel import db, User, OAuth2Client, OAuth2Token
from source.auth import require_oauth, authorization

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

        # Standard & validate ipv4 ipv6 input
        ipv4 = args['ipv4'].lower()
        ipv6 = args['ipv6'].lower()

        if ipv4 not in ['true', 'false'] or ipv6 not in ['true', 'false']:
            return {
                "success": False,
                "error": "Only enter true/false for ipv4 & ipv6"
            }, 400

        # Define add rule condition #
        # State the condition flags
        default_rule = False
        with_direction_rule = False
        with_source_ip_rule = False
        with_direction_source_ip_rule = False

        # Determine rule condition
        if not args['direction'] and not args['source']:
            default_rule = True
        elif args['direction'] and not args['source']:
            with_direction_rule = True
        elif not args['direction'] and args['source']:
            with_source_ip_rule = True
        elif args['direction'] and args['source']:
            with_direction_source_ip_rule = True

        print(f"default_rule: {default_rule}")
        print(f"with_direction_rule: {with_direction_rule}")
        print(f"with_source_ip_rule: {with_source_ip_rule}")
        print(f"with_direction_source_ip_rule: {with_direction_source_ip_rule}")

        return jsonify({
                "success": True
            })

        # try:
        #     port = args['port']

        #     # Build and run the ufw command
        #     cmd = ["sudo", "/usr/sbin/ufw", "allow", f"{port}/tcp"]
        #     result = subprocess.run(cmd, capture_output=True, text=True)
            
        #     return jsonify({
        #         "success": True,
        #         "message": f"Port {port} is added successfully"
        #     })
        # except Exception as e:
        #     return jsonify({"success": False, "error": str(e)}), 500

    ## Delete Request
    @require_oauth()
    def delete(self):
        """
        Delete firewall rule by port/service
        """
        parser = reqparse.RequestParser()
        parser.add_argument('port', type=str, required=False, help='Port number (optional if service is provided)')
        parser.add_argument('service', type=str, required=False, help='Service name (optional if port is provided)')
        parser.add_argument('protocol', type=str, required=False, default='tcp', choices=['tcp', 'udp'], help='Protocol (tcp/udp)')
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

        if ipv4 not in ['true', 'false'] or ipv6 not in ['true', 'false']:
            return {
                "success": False,
                "error": "Only enter true/false for ipv4 & ipv6"
            }, 400
        
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
                    "error": f"No matching rules found for port {target_port}/{args['protocol']} with IPv4:{ipv4} IPv6:{ipv6}"
                }, 404
            
            # Delete the matching rules
            deletion_results = self._delete_rules(matching_rules)
            
            return {
                "success": True,
                "message": f"Successfully deleted {len(deletion_results)} rule(s) for port {target_port}/{args['protocol']}",
                "deleted_rules": deletion_results,
                "details": {
                    "port": target_port,
                    "protocol": args['protocol'],
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "service": args['service'] if args['service'] else None
                }
            }, 200
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }, 500
    
    def _service_to_port(self, service_name):
        """
        Convert service name to default port number
        """
        service_ports = {
            'http': '80',
            'https': '443',
            'ssh': '22',
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
            print(f"Error parsing rule with number: {line}, Error: {e}")
            return None
    
    def _find_matching_rules(self, rules, target_port, protocol, ipv4, ipv6):
        """
        Find rules that match the specified criteria
        """
        matching_rules = []
        
        # Debug Logging
        # print(f"=== MATCHING CRITERIA ===")
        # print(f"Looking for: port={target_port}, protocol={protocol}, ipv4={ipv4}, ipv6={ipv6}")
        
        for rule in rules:
            # print(f"Checking rule {rule['rule_number']}: {rule['port']}/{rule['protocol']} IPv4:{rule['ipv4']} IPv6:{rule['ipv6']}")
            
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
            
           # Match if rule matches EITHER IP version
            if not ((ipv4 and rule['ipv4']) or (ipv6 and rule['ipv6'])):
                continue
            
            # Check if it's an ALLOW rule (you might want to handle DENY rules differently)
            if rule['action'] != 'ALLOW':
                # print(f"  - Action mismatch: {rule['action']} != ALLOW")
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
                
                deletion_results.append({
                    "rule_number": rule['rule_number'],
                    "port": rule['port'],
                    "protocol": rule['protocol'],
                    "ipv4": rule['ipv4'],
                    "ipv6": rule['ipv6'],
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                })
                
            except Exception as e:
                deletion_results.append({
                    "rule_number": rule['rule_number'],
                    "port": rule['port'],
                    "protocol": rule['protocol'],
                    "ipv4": rule['ipv4'],
                    "ipv6": rule['ipv6'],
                    "success": False,
                    "error": str(e)
                })
        
        return deletion_results
    
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
        is_ipv6 = '(v6)' in port_info or '(v6)' in source_info
        clean_source = re.sub(r'\s*\(v6\)\s*', '', source_info).strip()
        return clean_source, not is_ipv6, is_ipv6