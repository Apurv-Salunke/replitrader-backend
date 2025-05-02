- signup with email
    fields: name, email, phone
    returns: Success 
    send OTP to email and keep the user details in a cache (not in the main DB)

- verify otp
    fields: email + OTP
    returns: jwt token
    verifies against OTP stored in cache

- resend OTP
    fields: email
    returns: sucess
    sends OTP and stores it in cache

- login with email
    fields: email
    returns: sucess
    sends OTP to email and stores it in cache


flow:
signup -> verify OTP
login -> verify OTP

User schema:
    name
    email
    phone
    role (creator or user)
    created at
    updated at 