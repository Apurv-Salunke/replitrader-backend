import os
import jwt
import random
import string
import datetime
import functools # For decorator
from flask import Blueprint, request, current_app, url_for, redirect, g # Added g
from database.user_db import find_user_by_email, add_user, UserRole, db_session, User # Added User model
from utils.cache import get_cache, set_cache, delete_cache
from utils.response import success_response, error_response
from utils.email_utils import send_otp_email
from limiter import limiter # Assuming limiter is configured in app factory
from extensions import oauth # Import the oauth instance

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

OTP_CACHE_TTL = 300 # 5 minutes
JWT_EXPIRATION_DELTA = datetime.timedelta(hours=24)

# Decorator to verify JWT token
def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token_type, token = auth_header.split()
                if token_type.lower() != 'bearer':
                    token = None # Not a Bearer token
            except ValueError:
                token = None # Malformed header

        if not token:
            return error_response("Authentication Token is missing!", error_code="TOKEN_MISSING"), 401

        try:
            # Decode and verify the token
            jwt_secret = current_app.config.get('JWT_SECRET_KEY')
            if not jwt_secret:
                 print("[ERROR] JWT_SECRET_KEY not configured for token verification!")
                 return error_response("Server configuration error", error_code="CONFIG_ERROR"), 500

            payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            # Store payload in Flask's g object for access in the route
            g.user_payload = payload
            # Optionally fetch user object here and store in g.user if needed frequently
            # g.current_user = User.query.get(payload['user_id'])
            # if not g.current_user:
            #     return error_response("User associated with token not found", error_code="USER_NOT_FOUND"), 401

        except jwt.ExpiredSignatureError:
            return error_response("Token has expired!", error_code="TOKEN_EXPIRED"), 401
        except jwt.InvalidTokenError:
            return error_response("Invalid Token!", error_code="TOKEN_INVALID"), 401
        except Exception as e:
             print(f"[ERROR] Token verification error: {e}")
             return error_response("Token verification failed", error_code="TOKEN_VERIFICATION_FAILED"), 401

        return f(*args, **kwargs)
    return decorated

def generate_otp(length=6):
    """Generates a random OTP."""
    return ''.join(random.choices(string.digits, k=length))

@auth_bp.errorhandler(429)
def ratelimit_handler(e):
    return error_response("Rate limit exceeded", error_code="RATE_LIMIT_EXCEEDED"), 429

# Rate limits can be adjusted as needed
@auth_bp.route('/signup', methods=['POST'])
@limiter.limit("10 per hour")
def signup():
    data = request.get_json()
    if not data:
        return error_response("Missing JSON payload", error_code="BAD_REQUEST"), 400

    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone') # Optional

    if not name or not email:
        return error_response("Missing required fields: name, email", error_code="BAD_REQUEST"), 400

    # Basic email format validation (consider using a library like email_validator)
    if "@" not in email or "." not in email:
         return error_response("Invalid email format", error_code="INVALID_EMAIL"), 400

    # Check if user already exists in DB
    if find_user_by_email(email):
        return error_response("User with this email already exists", error_code="USER_EXISTS"), 409

    otp = generate_otp()
    cache_key = f"otp:signup:{email}"
    user_details = {"name": name, "email": email, "phone": phone, "otp": otp}

    # Store user details and OTP in cache
    if not set_cache(cache_key, user_details, ttl=OTP_CACHE_TTL):
        return error_response("Failed to initiate signup process", error_code="CACHE_ERROR"), 500

    # Send OTP via email
    if not send_otp_email(email, otp):
         # Note: send_otp_email currently logs and returns True even on failure for testing
         # In production, handle email sending failure appropriately
         print(f"Warning: Failed to send OTP email to {email}, but proceeding.")
         # Consider returning an error here in a real deployment if email is critical
         # return error_response("Failed to send OTP email", error_code="EMAIL_ERROR"), 500

    return success_response(message="OTP sent to your email for verification.")

@auth_bp.route('/verify-otp', methods=['POST'])
@limiter.limit("20 per hour")
def verify_otp():
    data = request.get_json()
    if not data:
        return error_response("Missing JSON payload", error_code="BAD_REQUEST"), 400

    email = data.get('email')
    otp_provided = data.get('otp')

    if not email or not otp_provided:
        return error_response("Missing required fields: email, otp", error_code="BAD_REQUEST"), 400

    # Check both signup and login OTP caches
    signup_cache_key = f"otp:signup:{email}"
    login_cache_key = f"otp:login:{email}"

    cached_data_signup = get_cache(signup_cache_key)
    cached_data_login = get_cache(login_cache_key)

    user_details = None
    is_signup = False
    cache_key_to_delete = None

    if cached_data_signup and cached_data_signup.get("otp") == otp_provided:
        user_details = cached_data_signup
        is_signup = True
        cache_key_to_delete = signup_cache_key
    elif cached_data_login and cached_data_login.get("otp") == otp_provided:
        user_details = cached_data_login # Contains only OTP for login
        cache_key_to_delete = login_cache_key
    else:
        return error_response("Invalid or expired OTP", error_code="INVALID_OTP"), 400

    # --- OTP Verified --- 

    user = find_user_by_email(email)

    if is_signup:
        if not user_details:
             return error_response("Signup data missing from cache", error_code="CACHE_ERROR"), 500
        # Create user in DB if it was a signup
        user = add_user(
            name=user_details['name'],
            email=user_details['email'],
            phone=user_details.get('phone')
            # role=UserRole.USER # Removed default role assignment
        )
        if not user:
            return error_response("Failed to create user account", error_code="DB_ERROR"), 500
    elif not user:
         # This case should ideally not happen if login OTP was generated,
         # but check just in case.
         return error_response("User not found for login verification", error_code="USER_NOT_FOUND"), 404

    # Generate JWT Token
    try:
        jwt_secret = current_app.config.get('JWT_SECRET_KEY')
        if not jwt_secret:
             print("[ERROR] JWT_SECRET_KEY not configured!")
             return error_response("Server configuration error", error_code="CONFIG_ERROR"), 500

        payload = {
            'user_id': user.id,
            'email': user.email,
            'role': user.role.value if user.role else None, # Handle None role
            'exp': datetime.datetime.now(datetime.timezone.utc) + JWT_EXPIRATION_DELTA
        }
        token = jwt.encode(payload, jwt_secret, algorithm="HS256")

        # Prepare profile data to return
        profile_data = {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "avatar_url": user.avatar_url,
            "role": user.role.value if user.role else None,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None
        }

        # Delete OTP from cache after successful verification
        if cache_key_to_delete:
            delete_cache(cache_key_to_delete)

        return success_response(data={'token': token, 'profile': profile_data}, message="Verification successful.")

    except jwt.PyJWTError as e:
        print(f"[ERROR] Failed to generate JWT: {e}")
        return error_response("Failed to generate authentication token", error_code="JWT_ERROR"), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error during verification: {e}")
        return error_response("An unexpected error occurred", error_code="UNEXPECTED_ERROR"), 500

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    data = request.get_json()
    if not data:
        return error_response("Missing JSON payload", error_code="BAD_REQUEST"), 400

    email = data.get('email')
    if not email:
        return error_response("Missing required field: email", error_code="BAD_REQUEST"), 400

    # Check if user exists
    user = find_user_by_email(email)
    if not user:
        return error_response("User not found with this email", error_code="USER_NOT_FOUND"), 404

    otp = generate_otp()
    cache_key = f"otp:login:{email}"
    otp_data = {"otp": otp}

    # Store OTP in cache
    if not set_cache(cache_key, otp_data, ttl=OTP_CACHE_TTL):
        return error_response("Failed to initiate login process", error_code="CACHE_ERROR"), 500

    # Send OTP via email
    if not send_otp_email(email, otp):
        print(f"Warning: Failed to send login OTP email to {email}, but proceeding.")
        # Consider returning an error here in production
        # return error_response("Failed to send OTP email", error_code="EMAIL_ERROR"), 500

    return success_response(message="OTP sent to your email for login.")

@auth_bp.route('/resend-otp', methods=['POST'])
@limiter.limit("5 per hour")
def resend_otp():
    data = request.get_json()
    if not data:
        return error_response("Missing JSON payload", error_code="BAD_REQUEST"), 400

    email = data.get('email')
    if not email:
        return error_response("Missing required field: email", error_code="BAD_REQUEST"), 400

    # Check if there is an active OTP process (signup or login)
    signup_cache_key = f"otp:signup:{email}"
    login_cache_key = f"otp:login:{email}"

    cached_data = get_cache(signup_cache_key) or get_cache(login_cache_key)
    cache_key_to_update = signup_cache_key if get_cache(signup_cache_key) else login_cache_key if get_cache(login_cache_key) else None

    if not cached_data or not cache_key_to_update:
        return error_response("No active OTP process found for this email. Please start signup or login first.", error_code="NO_ACTIVE_OTP"), 404

    # Generate new OTP and update cache
    new_otp = generate_otp()
    cached_data['otp'] = new_otp # Update the OTP in the existing cached data

    if not set_cache(cache_key_to_update, cached_data, ttl=OTP_CACHE_TTL):
         return error_response("Failed to update OTP cache", error_code="CACHE_ERROR"), 500

    # Resend OTP via email
    if not send_otp_email(email, new_otp):
        print(f"Warning: Failed to resend OTP email to {email}, but proceeding.")
        # Consider returning an error here in production
        # return error_response("Failed to send OTP email", error_code="EMAIL_ERROR"), 500

    return success_response(message="New OTP sent to your email.")

# --- Google OAuth Routes ---

@auth_bp.route('/google/login')
@limiter.limit("20 per hour") # Apply rate limiting
def google_login():
    # Define the callback URL for Google to redirect to
    # Make sure this matches the one configured in Google Cloud Console
    redirect_uri = url_for('auth.google_callback', _external=True)
    # Use Authlib to generate the authorization URL and redirect the user
    return oauth.google.authorize_redirect(redirect_uri)

@auth_bp.route('/google/callback')
@limiter.limit("20 per hour") # Apply rate limiting to callback
def google_callback():
    try:
        # Authorize the access token from Google
        token = oauth.google.authorize_access_token()
        # Fetch user information from Google using the token
        # Authlib automatically handles verifying the id_token
        userinfo = token.get('userinfo')

        if not userinfo or not userinfo.get('email_verified'):
            return error_response("Google authentication failed or email not verified", error_code="GOOGLE_AUTH_FAILED"), 400

        email = userinfo.get('email')
        name = userinfo.get('name') or userinfo.get('given_name') # Get name
        avatar = userinfo.get('picture') # Get avatar URL

        if not email:
             return error_response("Email not provided by Google", error_code="GOOGLE_EMAIL_MISSING"), 400

        # Find or create the user in your database
        user = find_user_by_email(email)
        if not user:
            # Create a new user if they don't exist
            user = add_user(
                name=name,
                email=email,
                avatar_url=avatar # Pass avatar URL
                # phone=None, # Phone not provided by Google OAuth
                # role=UserRole.USER # Removed default role assignment
            )
            if not user:
                return error_response("Failed to create user account after Google auth", error_code="DB_ERROR"), 500
            print(f"New user created via Google OAuth: {email}")
        else:
            # Update existing user's avatar if it has changed (or if it was null)
            if user.avatar_url != avatar:
                user.avatar_url = avatar
                try:
                    db_session.commit() # Commit the change
                    print(f"Updated avatar for existing user: {email}")
                except Exception as db_err:
                    db_session.rollback()
                    print(f"[WARN] Failed to update avatar for {email}: {db_err}")
            print(f"Existing user logged in via Google OAuth: {email}")

        # --- User Found or Created - Generate Application JWT ---
        jwt_secret = current_app.config.get('JWT_SECRET_KEY')
        if not jwt_secret:
             print("[ERROR] JWT_SECRET_KEY not configured!")
             return error_response("Server configuration error", error_code="CONFIG_ERROR"), 500

        payload = {
            'user_id': user.id,
            'email': user.email,
            'role': user.role.value if user.role else None, # Handle None role
            'exp': datetime.datetime.now(datetime.timezone.utc) + JWT_EXPIRATION_DELTA
        }
        app_token = jwt.encode(payload, jwt_secret, algorithm="HS256")

        # --- Redirect to Frontend Callback with Token --- 
        # Construct frontend callback URL with token
        frontend_callback_url = os.getenv('FRONTEND_AUTH_CALLBACK_URL', 'http://localhost:3000/auth/callback')
        redirect_url_base = f"{frontend_callback_url}?token={app_token}"

        # Append role if it exists (it will be None for initial signup)
        redirect_url_final = redirect_url_base
        if user.role:
            redirect_url_final += f"&role={user.role.value}"

        return redirect(redirect_url_final)

    except Exception as e:
        print(f"[ERROR] Google OAuth callback error: {e}")
        # Redirect to frontend callback with error message
        frontend_callback_url = os.getenv('FRONTEND_AUTH_CALLBACK_URL', 'http://localhost:3000/auth/callback')
        error_message = 'Google authentication failed. Please try again.'
        # Simple URL encoding for the error message (replace spaces)
        encoded_error = error_message.replace(' ', '+')
        redirect_url_with_error = f"{frontend_callback_url}?error={encoded_error}"
        return redirect(redirect_url_with_error)

@auth_bp.route('/profile', methods=['GET'])
@token_required # Protect this route with JWT verification
def get_profile():
    """Returns the profile information for the authenticated user."""
    try:
        user_id = g.user_payload.get('user_id')
        if not user_id:
             # This shouldn't happen if token_required worked, but check anyway
             return error_response("User ID not found in token payload", error_code="TOKEN_PAYLOAD_ERROR"), 401

        # Fetch the user from the database
        user = User.query.get(user_id)

        if not user:
            return error_response("User not found in database", error_code="USER_NOT_FOUND"), 404

        # Prepare profile data
        profile_data = {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "avatar_url": user.avatar_url,
            "role": user.role.value if user.role else None, # Use enum value or None
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None
        }

        return success_response(data=profile_data)

    except Exception as e:
        print(f"[ERROR] Failed to get profile for user_id {g.user_payload.get('user_id', 'unknown')}: {e}")
        return error_response("Failed to retrieve user profile", error_code="PROFILE_FETCH_FAILED"), 500

@auth_bp.route('/profile', methods=['PATCH'])
@token_required # Protect this route
def update_profile():
    """Updates the profile information (name, phone) for the authenticated user."""
    user_id = g.user_payload.get('user_id')
    if not user_id:
        return error_response("User ID not found in token payload", error_code="TOKEN_PAYLOAD_ERROR"), 401

    data = request.get_json()
    if not data:
        return error_response("Missing JSON payload", error_code="BAD_REQUEST"), 400

    # Fetch the user from the database
    user = User.query.get(user_id)
    if not user:
        return error_response("User not found in database", error_code="USER_NOT_FOUND"), 404

    updated = False
    # Update allowed fields if present in the request data
    if 'name' in data:
        new_name = data['name']
        if isinstance(new_name, str) and new_name.strip():
            user.name = new_name.strip()
            updated = True
        else:
             return error_response("Invalid value provided for name", error_code="INVALID_INPUT"), 400

    if 'phone' in data:
        # Allow setting phone to null/empty or a string
        new_phone = data['phone']
        if new_phone is None:
             user.phone = None
             updated = True
        elif isinstance(new_phone, str):
             user.phone = new_phone.strip()
             updated = True
        else:
             return error_response("Invalid value provided for phone", error_code="INVALID_INPUT"), 400

    if 'role' in data:
        # --- Role Update Logic ---
        # Check if role is already set
        if user.role is not None:
            return error_response("User role has already been set and cannot be changed.", error_code="ROLE_ALREADY_SET"), 403 # 403 Forbidden

        # If role is currently NULL, proceed to set it
        new_role_str = data['role']
        try:
            # Validate and convert string to UserRole enum
            new_role_enum = UserRole(new_role_str.lower()) # Convert to lowercase for case-insensitivity
            user.role = new_role_enum
            updated = True
        except ValueError:
            # Invalid role value provided
             allowed_roles = [r.value for r in UserRole]
             return error_response(f"Invalid value provided for role. Must be one of: {allowed_roles}", error_code="INVALID_INPUT"), 400
        # --- End Role Update Logic ---

    if not updated:
        return error_response("No valid fields provided for update (name, phone, role)", error_code="NO_UPDATE_FIELDS"), 400

    try:
        db_session.commit()
        # Prepare updated profile data to return
        profile_data = {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "avatar_url": user.avatar_url,
            "role": user.role.value if user.role else None, # Use enum value or None
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None # May not reflect immediate change
        }
        return success_response(data=profile_data, message="Profile updated successfully.")

    except Exception as e:
        db_session.rollback()
        print(f"[ERROR] Failed to update profile for user_id {user_id}: {e}")
        return error_response("Failed to update profile", error_code="PROFILE_UPDATE_FAILED"), 500

# Note: The original /broker and /logout routes depended on the old session/auth system.
# A new JWT-based logout mechanism (e.g., token blocklist) or reliance on client-side token deletion
# would be needed if explicit server-side logout is required.
# Broker login flow needs complete redesign based on JWT and broker requirements.
