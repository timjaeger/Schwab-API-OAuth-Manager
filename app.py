import os
import logging
from flask import Flask, render_template, redirect, url_for, session, request
from requests_oauthlib import OAuth2Session
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

@app.route('/callback')
def callback():
    schwab = OAuth2Session(client_id, state=session['oauth_state'], redirect_uri=callback_url)
    try:
        token = schwab.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url)
        session['oauth_token'] = token
        logger.info("Successfully obtained OAuth token")
        return redirect(url_for('profile'))
    except Exception as e:
        logger.error(f"Error during OAuth callback: {str(e)}")
        return "Authentication failed", 400

@app.route('/profile')
def profile():
    if 'oauth_token' not in session:
        logger.warning("Attempted to access profile without authentication")
        return redirect(url_for('index'))
    
    schwab = OAuth2Session(client_id, token=session['oauth_token'])
    try:
        user_info = schwab.get('https://api.schwab.com/v1/user/profile').json()
        logger.info("Successfully retrieved user profile")
        return render_template('profile.html', user_info=user_info)
    except Exception as e:
        logger.error(f"Error retrieving user profile: {str(e)}")
        return "Failed to retrieve user information", 400

@app.route('/logout')
def logout():
    session.pop('oauth_token', None)
    session.pop('oauth_state', None)
    logger.info("User logged out")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
