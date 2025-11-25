''' External Library Import '''
from flask import Flask
from flask_restful import Api

# Setup Flask, REST API
app = Flask(__name__, 
            static_folder='frontend',
            static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firewallx_oauth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production!
api = Api(app)