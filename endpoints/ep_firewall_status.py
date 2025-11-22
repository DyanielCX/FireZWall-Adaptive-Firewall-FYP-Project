''' External Library Import '''
from flask_restful import Resource
from flask import request
import subprocess
import re

''' Internal File Import '''
from source.auth import require_oauth
from source.syslog_record import syslog_create, get_username_with_token

class FirewallStatus(Resource):
    @require_oauth()
    def get(self):
        """
        Get current firewall status with combined IPv4/IPv6 rules
        """
        try:
            cmd = ["sudo", "ufw", "status", "numbered"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                combined_rules = self._parse_and_combine_rules_simple(result.stdout)

                # ---Logs Record--- #
                # Get the OAuth token & username
                auth_header = request.headers.get('Authorization')
                access_token = auth_header.split(' ')[1]
                Username = get_username_with_token(access_token)

                # Log info
                level = "INFO"
                event_type = "VIEW_FIREWALL_STATUS_SUCCESS"
                module = "firewall"
                message = f"View the firewall status succeed"
                username = Username
                ip_addr = request.remote_addr
                method = "GET"
                endpoint = "/api/firewall/status"

                syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, None)
                
                # Return dictionary
                return {
                    "success": True,
                    "Firewall-Status": combined_rules
                }, 200
            else:
                # ---Logs Record--- #
                # Get the OAuth token & username
                auth_header = request.headers.get('Authorization')
                access_token = auth_header.split(' ')[1]
                Username = get_username_with_token(access_token)

                # Logs Record
                level = "ERROR"
                event_type = "GET_UFW_STATUS_FAILED"
                module = "firewall"
                message = result.stderr
                username = Username
                ip_addr = request.remote_addr
                method = "GET"
                endpoint = "/api/firewall/status"

                syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, None)

                return {
                    "success": False,
                    "error": result.stderr
                }, 500
                
        except Exception as e:
            # Get the OAuth token & username
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            Username = get_username_with_token(access_token)

            # Logs Record
            level = "ERROR"
            event_type = "EP_FIREWALL_STATUS_SYS_ERROR"
            module = "firewall"
            message = str(e)
            username = Username
            ip_addr = request.remote_addr
            method = "GET"
            endpoint = "/api/firewall/status"

            syslog_create(level, event_type, module, message, username, ip_addr, method, endpoint, None)
            
            return {
                "success": False,
                "error": str(e)
            }, 500
    
    def _parse_and_combine_rules_simple(self, output):
        """
        Simple version that just combines rules without tracking details
        """
        individual_rules = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if (not line or 
                'Status:' in line or 
                ('To' in line and 'Action' in line and 'From' in line)):
                continue
            
            if line.startswith('[') and ']' in line:
                rule = self._parse_single_rule(line)
                if rule:
                    individual_rules.append(rule)
        
        # Combine rules
        combined_rules = {}
        
        for rule in individual_rules:
            key = (rule["port"], rule["protocol"], rule["action"], rule["direction"], rule["source"])
            
            if key in combined_rules:
                existing_rule = combined_rules[key]
                existing_rule["ipv4"] = existing_rule["ipv4"] or rule["ipv4"]
                existing_rule["ipv6"] = existing_rule["ipv6"] or rule["ipv6"]
            else:
                combined_rules[key] = rule.copy()
        
        return list(combined_rules.values())
    
    def _parse_single_rule(self, line):
        """
        Parse a single UFW rule line
        """
        try:
            end_bracket = line.find(']')
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
                "action": action,
                "port": port,
                "protocol": protocol,
                "direction": direction,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "source": source
            }
            
        except Exception as e:
            print(f"Error parsing rule: {line}, Error: {e}")
            return None
    
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
