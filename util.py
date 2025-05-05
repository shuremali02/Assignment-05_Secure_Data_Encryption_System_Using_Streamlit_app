import hashlib
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv()  # Load variables from .env file 

KEY = os.getenv("FERNET_KEY")
print(KEY)
try:
    
    if not KEY:
        raise Exception("FERNET_KEY not found in environment variables")
    cipher = Fernet(KEY.encode())  # Convert string to bytes
# cipher = Fernet(KEY)
except ValueError as e:
    print("Error ",e)

print("Cipher initialized successfully ✅")


# In-memory data storage
stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}
failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None