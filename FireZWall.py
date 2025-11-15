''' External Library Import '''
from flask import jsonify
import threading

''' Internal File Import '''
from config import app, api
from instance.create_db import init_database
from dbModel import User, OAuth2Client
from source.cowrie_conf import cowrie_start, cowrie_stop, cowrie_watcher
from endpoints.ep_auth import Login, Register, RefreshToken, Logout, LogoutAll
from endpoints.ep_firewall import Firewall
from endpoints.ep_firewall_status import FirewallStatus
from endpoints.ep_honeypot import honeypot_report


# API Routes
api.add_resource(Login, '/api/login')
api.add_resource(Register, '/api/register')
api.add_resource(RefreshToken, '/api/refresh-token')
api.add_resource(Logout, '/api/logout')
api.add_resource(LogoutAll, '/api/logout-all')
api.add_resource(Firewall, '/api/firewall')
api.add_resource(FirewallStatus, '/api/firewall/status')
api.add_resource(honeypot_report, '/api/honeypot/reports')

@app.route('/')
def index():
    return '<h1>Flask REST API with OAuth 2.0</h1>'

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
        app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=('SSL_cert/cert.pem', 'SSL_cert/key.pem'))
    
    finally:
        cowrie_stop()