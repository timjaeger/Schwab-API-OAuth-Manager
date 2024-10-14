import os
import logging
from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from requests_oauthlib import OAuth2Session
from config import Config
from urllib.parse import urlencode, parse_qs
import requests
from datetime import datetime, timedelta, timezone
import base64
import json

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

def write_tokens_to_file(tokens):
    token_data = {
        "access_token_issued": datetime.now(timezone.utc).isoformat(),
        "refresh_token_issued": datetime.now(timezone.utc).isoformat(),
        "token_dictionary": tokens
    }
    with open('tokens.json', 'w') as f:
        json.dump(token_data, f, indent=4)

def refresh_token():
    if 'refresh_token' not in session:
        logger.error("No refresh token available")
        return None

    refresh_token = session['refresh_token']
    headers = {
        'Authorization': f"Basic {base64.b64encode(bytes(f'{client_id}:{client_secret}', 'utf-8')).decode('utf-8')}",
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }

    try:
        response = requests.post(token_url, headers=headers, data=data)
        response.raise_for_status()
        token_data = response.json()

        session['access_token'] = token_data['access_token']
        session['refresh_token'] = token_data.get('refresh_token', refresh_token)
        session['token_expiry'] = datetime.now(timezone.utc) + timedelta(seconds=token_data.get('expires_in', 3600))

        write_tokens_to_file(token_data)

        logger.info("Successfully refreshed OAuth token")
        return token_data['access_token']
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        return None

def get_valid_token():
    if 'access_token' not in session or 'token_expiry' not in session:
        logger.warning("No access token or expiry time in session")
        return None

    time_until_expiry = session['token_expiry'] - datetime.now(timezone.utc)
    logger.info(f"Time until token expiry: {time_until_expiry}")

    if datetime.now(timezone.utc) >= session['token_expiry']:
        logger.info("Token expired, refreshing...")
        return refresh_token()
    
    logger.info("Using existing valid token")
    return session['access_token']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    authorization_url = f"https://api.schwabapi.com/v1/oauth/authorize?client_id={client_id}&redirect_uri={callback_url}"
    logger.info(f"Initiating OAuth flow, redirecting to: {authorization_url}")
    return render_template('login.html', auth_url=authorization_url)

@app.route('/process_redirect', methods=['POST'])
def process_redirect():
    redirect_url = request.json['redirect_url']
    try:
        # Extract the code from the URL
        code = f"{redirect_url[redirect_url.index('code=')+5:redirect_url.index('%40')]}@"
        
        # Prepare headers and data for token request
        headers = {
            'Authorization': f"Basic {base64.b64encode(bytes(f'{client_id}:{client_secret}', 'utf-8')).decode('utf-8')}",
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://127.0.0.1'
        }
        
        # Make the token request
        response = requests.post('https://api.schwabapi.com/v1/oauth/token', headers=headers, data=data)
        response.raise_for_status()
        token_data = response.json()

        # Store the tokens securely
        session['access_token'] = token_data['access_token']
        session['refresh_token'] = token_data.get('refresh_token')
        session['token_expiry'] = datetime.now(timezone.utc) + timedelta(seconds=token_data.get('expires_in', 3600))
        session['logged_in'] = True
        
        write_tokens_to_file(token_data)
        
        logger.info("Successfully obtained OAuth token")
        return jsonify({"success": True, "profile_url": url_for('profile', _external=True)})
    except Exception as e:
        logger.error(f"Error processing redirect URL: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/profile')
def profile():
    logger.info("Accessing profile route")
    access_token = get_valid_token()
    if not access_token:
        logger.warning("No valid access token available, redirecting to login")
        return redirect(url_for('login'))
    
    try:
        headers = {'Authorization': f"Bearer {access_token}"}
        response = requests.get('https://api.schwabapi.com/v1/user/profile', headers=headers)
        response.raise_for_status()
        user_info = response.json()
        logger.info("Successfully retrieved user profile")
        return render_template('profile.html', user_info=user_info)
    except Exception as e:
        logger.error(f"Error retrieving user profile: {str(e)}")
        return render_template('error.html', error=str(e)), 400

@app.route('/logout')
def logout():
    session.pop('access_token', None)
    session.pop('refresh_token', None)
    session.pop('oauth_state', None)
    session.pop('token_expiry', None)
    session.pop('logged_in', None)
    logger.info("User logged out")
    return redirect(url_for('index'))

@app.route('/test_refresh')
def test_refresh():
    logger.info("Testing token refresh")
    session['token_expiry'] = datetime.now(timezone.utc) - timedelta(seconds=1)
    
    access_token = get_valid_token()
    if not access_token:
        return jsonify({"error": "Failed to refresh token"}), 400
    
    with open('tokens.json', 'r') as f:
        tokens = json.load(f)
    
    return jsonify({"message": "Token refreshed successfully", "tokens": tokens})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
