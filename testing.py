from flask import Flask,  request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api, reqparse, fields, marshal_with, abort
import subprocess

# Setup Flask, Database, REST API
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
api = Api(app)

# # Database Model
# class UserModel(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(80), unique=True, nullable=False)
#     email = db.Column(db.String(80), unique=True, nullable=False)

#     def __repr__(self):
#         return f"User(name = {self.name}, email = {self.email})"


''' Firewall testing '''
class Firewall(Resource):
    # Post Request
    # @marshal_with(UserFields)
    def post(self, port):
        try:
            # Build and run the ufw command
            cmd = ["sudo", "/usr/sbin/ufw", "allow", f"{port}/tcp"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return jsonify({
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # Delete Request
    # @marshal_with(UserFields)
    def delete(self, port):
        try:
            # Build and run the ufw command
            cmd = ["sudo", "/usr/sbin/ufw", "delete", f"{port}"]
            result = subprocess.run(cmd, input="y", capture_output=True, text=True)
            
            return jsonify({
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

# Create API Resource Endpoint
# api.add_resource(Users, '/api/users/')
# api.add_resource(User, '/api/user/<int:id>')
api.add_resource(Firewall, '/api/firewall/<int:port>')

# Prepare Route
@app.route('/')
def index():
    return '<h1>Flask REST API</h1>'

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)