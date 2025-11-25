''' External Library Import '''
from flask import jsonify, request
import threading
from flask import Flask, send_from_directory, jsonify, request
import os

''' Internal File Import '''
from config import app, api
from instance.create_db import init_database
from dbModel import User, OAuth2Client, OAuth2Token
from source.cowrie_conf import cowrie_start, cowrie_stop, cowrie_watcher
from endpoints.ep_auth import Login, RefreshToken, Logout, LogoutAll
from endpoints.ep_user_manage import ViewUser, Register, DeleteUser
from endpoints.ep_firewall import Firewall
from endpoints.ep_firewall_status import FirewallStatus
from endpoints.ep_honeypot import HoneypotReport
from endpoints.ep_syslog import ViewSyslog

from source.auth import require_oauth
from source.syslog_record import get_username_with_token


# API Routes
api.add_resource(Login, '/api/login')
api.add_resource(RefreshToken, '/api/refresh-token')
api.add_resource(Logout, '/api/logout')
api.add_resource(LogoutAll, '/api/logout-all')
api.add_resource(ViewUser, '/api/user/view')
api.add_resource(Register, '/api/user/register')
api.add_resource(DeleteUser, '/api/user/delete')
api.add_resource(Firewall, '/api/firewall')
api.add_resource(FirewallStatus, '/api/firewall/status')
api.add_resource(HoneypotReport, '/api/honeypot/reports')
api.add_resource(ViewSyslog, '/api/logs')

# @app.route('/')
# def index():
#     return '<h1>Flask REST API with OAuth 2.0</h1>'

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react(path):
    # If path is empty or is index.html
    if path == '' or path == 'index.html':
        return send_from_directory(app.static_folder, 'index.html')
    
    # If file exists in frontend folder, serve it
    file_path = os.path.join(app.static_folder, path)
    if os.path.exists(file_path):
        return send_from_directory(app.static_folder, path)
    
    # For all other routes (React Router), return index.html
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/test')
@require_oauth()
def test():
    auth_header = request.headers.get('Authorization')
    access_token = auth_header.split(' ')[1]

    # Get User ID
    token = OAuth2Token.query.filter_by(access_token=access_token).first()
    scope = token.scope
    user_ID = token.user_id

    # Get username
    user = User.query.filter_by(id=user_ID).first()
    role = user.role

    return {
        "scope": scope,
        "role": role
    }

@app.route('/api/test-db')
def test_db():
    try:
        user_count = User.query.count()
        client_count = OAuth2Client.query.count()
        return jsonify({
            'users': user_count,
            'clients': client_count,
            'status': 'Database connected successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        # app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=('SSL_cert/cert.pem', 'SSL_cert/key.pem'))
        app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=None)
    
    finally:
        cowrie_stop()