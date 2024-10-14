# Schwab OAuth Authentication App

## Description
This Flask-based web application demonstrates OAuth authentication with Schwab's API. It allows users to log in using their Schwab credentials, manages secure token storage, and implements a token refresh mechanism.

## Features
- OAuth 2.0 authentication flow with Schwab API
- Secure token storage and management
- Token refresh mechanism
- Display of account numbers after successful authentication

## Prerequisites
- Python 3.7+
- pip (Python package manager)

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create a .env file in the root directory with the following content:
   ```
   FLASK_SECRET_KEY=your_secure_secret_key
   SCHWAB_CLIENT_ID=your_schwab_client_id
   SCHWAB_CLIENT_SECRET=your_schwab_client_secret
   ```
   Replace `your_secure_secret_key`, `your_schwab_client_id`, and `your_schwab_client_secret` with your actual values.

## Usage

1. Start the Flask application:
   ```
   python main.py
   ```

2. Open a web browser and navigate to `http://localhost:5000`

3. Click on the "Login with Schwab" button to initiate the OAuth flow

4. After successful authentication, you will be redirected back to the application where you can view your account numbers and test the token refresh mechanism

## Project Structure
- `app.py`: Main Flask application setup
- `routes.py`: Contains all the route handlers for the application
- `config.py`: Configuration settings for the application
- `modules/oauth/`: Contains OAuth-related functionality (token writing, refreshing, and validation)
- `templates/`: HTML templates for the web interface
- `static/`: Static files (CSS, JavaScript)

## Security Considerations
- This application uses environment variables to store sensitive information
- Tokens are securely stored and refreshed as needed
- HTTPS should be used in a production environment to secure data in transit

## Disclaimer
This application is for demonstration purposes only. In a production environment, additional security measures should be implemented.

Please ensure you comply with Schwab's API usage policies and terms of service when using this application.
