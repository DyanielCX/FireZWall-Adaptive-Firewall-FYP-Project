''' External Library Import '''
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api, reqparse

''' Internal File Import '''
from config import app, api
from instance.create_db import init_database
from dbModel import db, User, OAuth2Client, OAuth2Token
from source.auth import require_oauth, authorization
from endpoints.ep_auth import Login, Register, RefreshToken, Logout, LogoutAll
from endpoints.ep_firewall import Firewall
from endpoints.ep_firewall_status import FirewallStatus
from source.cowrie_conf import cowrie_start, cowrie_stop, cowrie_watcher


# API Routes
api.add_resource(Login, '/api/login')
api.add_resource(Register, '/api/register')
api.add_resource(RefreshToken, '/api/refresh-token')
api.add_resource(Logout, '/api/logout')
api.add_resource(LogoutAll, '/api/logout-all')
api.add_resource(Firewall, '/api/firewall')
api.add_resource(FirewallStatus, '/api/firewall/status')

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

if __name__ == '__main__':
    cowrie_start()      # Start Cowrie
    cowrie_watcher()    # cowrie Log Event Watcher

    try:
        with app.app_context():
            init_database()
        # Run Flask with SSL context
        app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=('SSL_cert/cert.pem', 'SSL_cert/key.pem'))
    finally:
        cowrie_stop()