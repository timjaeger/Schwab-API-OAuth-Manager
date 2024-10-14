from datetime import datetime, timezone
from flask import session
from .token_refresher import refresh_token

def get_valid_token(client_id, client_secret, token_url, logger):
    if 'access_token' not in session or 'token_expiry' not in session:
        logger.warning("No access token or expiry time in session")
        return None

    time_until_expiry = session['token_expiry'] - datetime.now(timezone.utc)
    logger.info(f"Time until token expiry: {time_until_expiry}")

    if datetime.now(timezone.utc) >= session['token_expiry']:
        logger.info("Token expired, refreshing...")
        return refresh_token(client_id, client_secret, token_url, logger)
    
    logger.info("Using existing valid token")
    return session['access_token']
