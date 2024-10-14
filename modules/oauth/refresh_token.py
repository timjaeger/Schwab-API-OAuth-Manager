import os
import logging
import requests
import base64
from datetime import datetime, timedelta, timezone
from flask import session
from .write_tokens import write_tokens_to_file

logger = logging.getLogger(__name__)

client_id = os.getenv('SCHWAB_CLIENT_ID')
client_secret = os.getenv('SCHWAB_CLIENT_SECRET')
token_url = 'https://api.schwabapi.com/v1/oauth/token'

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
