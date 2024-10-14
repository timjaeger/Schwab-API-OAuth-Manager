import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY') or 'a_secure_secret_key'
    SCHWAB_CLIENT_ID = os.getenv('SCHWAB_CLIENT_ID')
    SCHWAB_CLIENT_SECRET = os.getenv('SCHWAB_CLIENT_SECRET')
