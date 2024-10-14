import os
import logging
from flask import Blueprint, render_template, redirect, url_for, session, request, jsonify, current_app
from requests_oauthlib import OAuth2Session
from urllib.parse import urlencode, parse_qs
import requests
from datetime import datetime, timedelta, timezone
import base64
import json

routes_bp = Blueprint('routes_bp', __name__)

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

@routes_bp.route('/')
def index():
    return render_template('index.html')

@routes_bp.route('/login')
def login():
    schwab = OAuth2Session(client_id, scope=scope, redirect_uri=callback_url)
    authorization_url, state = schwab.authorization_url(authorization_base_url)
    session['oauth_state'] = state
    logger.info(f"Initiating OAuth flow, redirecting to: {authorization_url}")
    return render_template('login_instructions.html', auth_url=authorization_url)

@routes_bp.route('/enter_redirect')
def enter_redirect():
    return render_template('enter_redirect.html')

@routes_bp.route('/process_redirect', methods=['GET', 'POST'])
def process_redirect():
    if request.method == 'POST':
        redirect_url = request.form['redirect_url']
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
            
            # Get account numbers
            base_url = "https://api.schwabapi.com/trader/v1/"
            account_response = requests.get(f'{base_url}/accounts/accountNumbers', headers={'Authorization': f'Bearer {token_data["access_token"]}'})
            account_response.raise_for_status()
            account_numbers = account_response.json()
            
            return jsonify({
                "message": "Successfully processed OAuth flow",
                "account_numbers": account_numbers,
                "token_info": {
                    "access_token": token_data['access_token'][:10] + '...',  # Show only first 10 characters
                    "expires_in": token_data.get('expires_in'),
                    "token_type": token_data.get('token_type')
                }
            })
        except Exception as e:
            logger.error(f"Error processing redirect URL: {str(e)}")
            return jsonify({"error": str(e)}), 400

    return render_template('enter_redirect.html')

@routes_bp.route('/profile')
def profile():
    logger.info("Accessing profile route")
    access_token = get_valid_token()
    if not access_token:
        logger.warning("No valid access token available, redirecting to login")
        return redirect(url_for('routes_bp.login'))
    
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

@routes_bp.route('/logout')
def logout():
    session.pop('access_token', None)
    session.pop('refresh_token', None)
    session.pop('oauth_state', None)
    session.pop('token_expiry', None)
    session.pop('logged_in', None)
    logger.info("User logged out")
    return redirect(url_for('routes_bp.index'))

@routes_bp.route('/test_refresh')
def test_refresh():
    logger.info("Testing token refresh")
    session['token_expiry'] = datetime.now(timezone.utc) - timedelta(seconds=1)
    
    access_token = get_valid_token()
    if not access_token:
        return jsonify({"error": "Failed to refresh token"}), 400
    
    with open('tokens.json', 'r') as f:
        tokens = json.load(f)
    
    return jsonify({
        "message": "Token refreshed successfully",
        "new_access_token": access_token[:10] + '...',  # Show only first 10 characters
        "expires_in": tokens['token_dictionary'].get('expires_in'),
        "token_type": tokens['token_dictionary'].get('token_type')
    })
