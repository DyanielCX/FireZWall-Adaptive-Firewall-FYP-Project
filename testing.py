''' External Library Import '''
from flask import request, jsonify
from flask_restful import Resource, reqparse
import subprocess
import ipaddress
import re


cmd = ["cowrie", "start"]
subprocess.run(cmd)