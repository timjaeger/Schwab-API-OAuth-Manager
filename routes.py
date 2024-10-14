from flask import render_template, redirect, url_for, session, request, jsonify
from datetime import datetime, timedelta, timezone
import base64
import json
import requests
from app import app, client_id, client_secret, authorization_base_url, token_url, scope, callback_url, logger
from modules.oauth import write_tokens_to_file, refresh_token, get_valid_token
from requests_oauthlib import OAuth2Session

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    schwab = OAuth2Session(client_id, scope=scope, redirect_uri=callback_url)
    authorization_url, state = schwab.authorization_url(authorization_base_url)
    session['oauth_state'] = state
    logger.info(f"Initiating OAuth flow, redirecting to: {authorization_url}")
    return render_template('login_instructions.html', auth_url=authorization_url)

@app.route('/enter_redirect')
def enter_redirect():
    return render_template('enter_redirect.html')

@app.route('/process_redirect', methods=['GET', 'POST'])
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
    
    access_token = get_valid_token(client_id, client_secret, token_url, logger)
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
