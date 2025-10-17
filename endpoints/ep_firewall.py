''' External Library Import '''
from flask import request, jsonify
from flask_restful import Resource, reqparse
import subprocess

''' Internal File Import '''
from dbModel import db, User, OAuth2Client, OAuth2Token
from source.auth import require_oauth, authorization

# Protected Firewall Endpoint
class Firewall(Resource):

    # Post Request
    @require_oauth()  # Requires valid OAuth token
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('port', type=str, required=True, help='Port number is required')
        
        args = parser.parse_args()
        
        try:
            port = args['port']

            # Build and run the ufw command
            cmd = ["sudo", "/usr/sbin/ufw", "allow", f"{port}/tcp"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return jsonify({
                "success": True,
                "message": f"Port {port} is added successfully"
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # Delete Request
    @require_oauth()
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument('port', type=str, required=True, help='Port number is required')
        
        args = parser.parse_args()

        try:
            port = args['port']

            # Build and run the ufw command
            cmd = ["sudo", "/usr/sbin/ufw", "delete", f"{port}"]
            result = subprocess.run(cmd, input="y", capture_output=True, text=True)
            
            return jsonify({
                "success": True,
                "message": f"Port {port} is deleted successfully"
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500