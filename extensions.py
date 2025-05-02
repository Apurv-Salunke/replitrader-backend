from flask_socketio import SocketIO
from authlib.integrations.flask_client import OAuth

socketio = SocketIO(cors_allowed_origins='*')

# Initialize Authlib OAuth registry
oauth = OAuth()
