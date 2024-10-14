from functools import wraps
from flask import session, redirect, url_for
from .token_validator import get_valid_token
from app import client_id, client_secret, token_url, logger

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            logger.warning("No access token in session, redirecting to login")
            return redirect(url_for('login'))

        access_token = get_valid_token(client_id, client_secret, token_url, logger)
        if not access_token:
            logger.error("Failed to get a valid token, redirecting to login")
            return redirect(url_for('login'))

        session['access_token'] = access_token
        return f(*args, **kwargs)

    return decorated_function
