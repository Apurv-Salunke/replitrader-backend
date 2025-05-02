import os
import jwt
import random
import string
import datetime
from flask import Blueprint, request, current_app
from database.user_db import find_user_by_email, add_user, UserRole
from utils.cache import get_cache, set_cache, delete_cache
from utils.response import success_response, error_response
from utils.email_utils import send_otp_email
from limiter import limiter # Assuming limiter is configured in app factory

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

OTP_CACHE_TTL = 300 # 5 minutes
JWT_EXPIRATION_DELTA = datetime.timedelta(hours=24)

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
            phone=user_details.get('phone'),
            role=UserRole.USER # Default role, adjust if needed
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
            'role': user.role.value, # Use the enum value
            'exp': datetime.datetime.now(datetime.timezone.utc) + JWT_EXPIRATION_DELTA
        }
        token = jwt.encode(payload, jwt_secret, algorithm="HS256")

        # Delete OTP from cache after successful verification
        if cache_key_to_delete:
            delete_cache(cache_key_to_delete)

        return success_response(data={'token': token}, message="Verification successful.")

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

# Note: The original /broker and /logout routes depended on the old session/auth system.
# A new JWT-based logout mechanism (e.g., token blocklist) or reliance on client-side token deletion
# would be needed if explicit server-side logout is required.
# Broker login flow needs complete redesign based on JWT and broker requirements.
