import os
import logging
from flask import Flask
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Schwab OAuth settings
client_id = os.getenv('SCHWAB_CLIENT_ID')
client_secret = os.getenv('SCHWAB_CLIENT_SECRET')
authorization_base_url = 'https://api.schwabapi.com/v1/oauth/authorize'
token_url = 'https://api.schwabapi.com/v1/oauth/token'
scope = ['openid', 'profile']
callback_url = 'https://127.0.0.1'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

from routes import *
