# cors.py

from flask_cors import CORS

# Initialize Flask-CORS without the app object
cors = CORS(origins=["http://localhost:3000"], supports_credentials=True)