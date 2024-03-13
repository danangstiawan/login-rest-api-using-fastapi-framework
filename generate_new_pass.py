import bcrypt

def create_new_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

new_password = create_new_password("password2024")
print("New Password Hashed:", new_password)
