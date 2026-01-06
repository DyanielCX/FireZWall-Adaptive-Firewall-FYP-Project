# ================================================ #
#       Flask Server Script for FireZWall API      #
# ================================================ #

# Remember to change the server IP address to your own
SERVER_IP = '192.168.253.134'

''' External Library Import '''
from flask import jsonify, request
import threading
from flask import send_from_directory, jsonify, request
import os

''' Internal File Import '''
from config import app, api
from instance.create_db import init_database
from source.cowrie_conf import cowrie_start, cowrie_stop, cowrie_watcher
from endpoints.ep_auth import Login, RefreshToken, Logout, LogoutAll
from endpoints.ep_user_manage import ViewUser, Register, DeleteUser, GetUserRole, GetUserName
from endpoints.ep_firewall import Firewall
from endpoints.ep_firewall_status import FirewallStatus
from endpoints.ep_firewall_cmn_SrvPort import CommonServicePort
from endpoints.ep_honeypot import HoneypotReport
from endpoints.ep_syslog import ViewSyslog


# API System Endpoints
api.add_resource(Login, '/api/login')
api.add_resource(RefreshToken, '/api/refresh-token')
api.add_resource(Logout, '/api/logout')
api.add_resource(LogoutAll, '/api/logout-all')
api.add_resource(ViewUser, '/api/user/view')
api.add_resource(Register, '/api/user/register')
api.add_resource(DeleteUser, '/api/user/delete')
api.add_resource(Firewall, '/api/firewall')
api.add_resource(FirewallStatus, '/api/firewall/status')
api.add_resource(CommonServicePort, '/api/firewall/svc-port')
api.add_resource(HoneypotReport, '/api/honeypot/reports')
api.add_resource(ViewSyslog, '/api/logs')

# API User Endpoints for frontend
api.add_resource(GetUserRole, '/api/user/getRole')
api.add_resource(GetUserName, '/api/user/getUsername')


# Front-End GUI Endpoints
@app.route('/')
def index():
    """
    Serve React app for root route
    """
    return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(404)
def not_found(e):
    """
    Catch all 404 errors and return React's index.html
    This allows React Router to handle the routing
    """
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    """
    Serve static files or React app
    """
    file_path = os.path.join(app.static_folder, path)
    
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return send_from_directory(app.static_folder, path)
    
    return send_from_directory(app.static_folder, 'index.html')


# === Cowrie HoneyPot Background Threads === #
def start_cowrie_thread():
    t = threading.Thread(target=cowrie_start, daemon=True)
    t.start()

def start_cowrie_watcher_thread():
    t = threading.Thread(target=run_cowrie_watcher_in_context, daemon=True)
    t.start()

def run_cowrie_watcher_in_context():
    with app.app_context():
        cowrie_watcher()

if __name__ == '__main__':

    # Start cowrie + watcher in background
    start_cowrie_thread()
    start_cowrie_watcher_thread()

    try:
        with app.app_context():
            init_database()
        
        # Run Flask with SSL context
        app.run(host=SERVER_IP, port=5000, debug=False, ssl_context=('SSL_cert/firezwall.crt', 'SSL_cert/firezwall.key'))
    
    finally:
        cowrie_stop()