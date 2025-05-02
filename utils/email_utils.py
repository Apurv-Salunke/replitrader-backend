import os
from flask_mail import Message
from flask import current_app

# This is a placeholder/mock email sending function.
# You'll need to configure Flask-Mail properly in your app factory
# and set environment variables like:
# MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD

# mail = Mail() # Initialize Flask-Mail; typically done in app factory

def send_otp_email(recipient_email: str, otp: str):
    """Sends an OTP email to the specified recipient."""
    try:
        # In a real app, mail instance would be initialized and configured in create_app()
        mail = current_app.extensions.get('mail')
        if not mail:
            print(f"[WARN] Flask-Mail not configured. OTP for {recipient_email}: {otp}")
            return True # Simulate success for testing without email setup

        subject = "Your One-Time Password (OTP)"
        sender = os.getenv("MAIL_DEFAULT_SENDER", "noreply@example.com")
        body = f"Your OTP is: {otp}\n\nThis code will expire in 5 minutes."

        msg = Message(subject, sender=sender, recipients=[recipient_email])
        msg.body = body

        mail.send(msg)
        print(f"OTP email sent successfully to {recipient_email}.")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send OTP email to {recipient_email}: {e}")
        # Fallback for testing: Print OTP to console if email fails
        print(f"[FALLBACK] OTP for {recipient_email}: {otp}")
        # return False # In production, you might return False
        return True # Simulate success for now to allow flow testing 