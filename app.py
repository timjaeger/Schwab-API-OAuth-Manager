import os
from flask import Flask
from config import Config
from routes import routes_bp

app = Flask(__name__)
app.config.from_object(Config)

# Register the Blueprint
app.register_blueprint(routes_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
