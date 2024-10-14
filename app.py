import os
import logging
from flask import Flask, render_template, redirect, url_for, session, request
from requests_oauthlib import OAuth2Session
from config import Config
from urllib.parse import urlencode, parse_qs
import requests

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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    schwab = OAuth2Session(client_id, scope=scope, redirect_uri=callback_url)
    authorization_url = f"{authorization_base_url}?client_id={client_id}&redirect_uri={callback_url}"
    session['oauth_state'] = schwab._state
    logger.info(f"Initiating OAuth flow, redirecting to: {authorization_url}")
    return redirect(authorization_url)

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
    if 'access_token' not in session:
        logger.warning("Attempted to access profile without authentication")
        return redirect(url_for('index'))
    
    try:
        headers = {'Authorization': f"Bearer {session['access_token']}"}
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
    logger.info("User logged out")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
