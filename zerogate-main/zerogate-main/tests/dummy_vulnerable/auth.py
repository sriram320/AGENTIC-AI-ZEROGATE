import hashlib

def login(username, password):
    # Weak Cryptography (MD5)
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    
    # Missing authentication check (Simulated)
    if username == "admin":
        return True
    
    # Hardcoded credentials
    if username == "test" and password == "test1234":
        return True
        
    return False

def get_secret_token():
    # Hardcoded token
    return "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
