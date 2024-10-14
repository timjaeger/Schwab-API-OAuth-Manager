import os
import logging
from flask import Flask, render_template, redirect, url_for, session, request
from requests_oauthlib import OAuth2Session
from config import Config
from urllib.parse import urlencode, parse_qs
import requests
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.from_object(Config)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Schwab OAuth settings
client_id = os.getenv('SCHWAB_CLIENT_ID')
client_secret = os.getenv('SCHWAB_CLIENT_SECRET')
authorization_base_url = 'https://api.schwabapi.com/v1/oauth/authorize'
token_url = 'https://api.schwab.com/oauth/token'
scope = ['openid', 'profile']
callback_url = 'https://127.0.0.1'

def refresh_token():
    if 'refresh_token' not in session:
        logger.error("No refresh token available")
        return None

    refresh_token = session['refresh_token']
    token_params = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': client_id,
        'client_secret': client_secret
    }

    try:
        response = requests.post(token_url, data=token_params)
        response.raise_for_status()
        token_data = response.json()

        session['access_token'] = token_data['access_token']
        session['refresh_token'] = token_data.get('refresh_token', refresh_token)
        session['token_expiry'] = datetime.now() + timedelta(seconds=30)  # Set to 30 seconds for testing

        logger.info("Successfully refreshed OAuth token")
        return token_data['access_token']
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        return None

def get_valid_token():
    if 'access_token' not in session or 'token_expiry' not in session:
        logger.warning("No access token or expiry time in session")
        return None

    time_until_expiry = session['token_expiry'] - datetime.now()
    logger.info(f"Time until token expiry: {time_until_expiry}")

    if datetime.now() >= session['token_expiry']:
        logger.info("Token expired, refreshing...")
        return refresh_token()
    
    logger.info("Using existing valid token")
    return session['access_token']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    schwab = OAuth2Session(client_id, scope=scope, redirect_uri=callback_url)
    authorization_url = f"{authorization_base_url}?client_id={client_id}&redirect_uri={callback_url}"
    session['oauth_state'] = schwab.state
    logger.info(f"Initiating OAuth flow, redirecting to: {authorization_url}")
    return render_template('login_instructions.html', auth_url=authorization_url)

@app.route('/enter_redirect')
def enter_redirect():
    return render_template('enter_redirect.html')

@app.route('/process_redirect', methods=['POST'])
def process_redirect():
    redirect_url = request.form['redirect_url']
    try:
        # Extract the code from the URL
        parsed_url = parse_qs(redirect_url.split('?')[1])
        code = parsed_url.get('code', [None])[0]
        
        if not code:
            raise ValueError("No code found in the redirect URL")

        # Make the token request
        token_params = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': callback_url,
            'client_id': client_id,
            'client_secret': client_secret
        }
        
        response = requests.post(token_url, data=token_params)
        response.raise_for_status()
        token_data = response.json()

        # Store the tokens securely
        session['access_token'] = token_data['access_token']
        session['refresh_token'] = token_data.get('refresh_token')
        session['token_expiry'] = datetime.now() + timedelta(seconds=30)  # Set to 30 seconds for testing
        
        logger.info("Successfully obtained OAuth token")
        return redirect(url_for('profile'))
    except Exception as e:
        logger.error(f"Error processing redirect URL: {str(e)}")
        return render_template('error.html', error=str(e)), 400

@app.route('/callback')
def callback():
    return redirect(url_for('enter_redirect'))

@app.route('/profile')
def profile():
    access_token = get_valid_token()
    if not access_token:
        logger.warning("No valid access token available")
        return redirect(url_for('login'))
    
    try:
        headers = {'Authorization': f"Bearer {access_token}"}
        response = requests.get('https://api.schwab.com/v1/user/profile', headers=headers)
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
    logger.info("User logged out")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
