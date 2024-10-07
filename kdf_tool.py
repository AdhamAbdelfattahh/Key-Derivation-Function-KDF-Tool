import os
import hashlib
import base64
from Crypto.Protocol.KDF import PBKDF2

def derive_key(password, salt, iterations=100000):
    """Derive a key from the given password and salt using PBKDF2."""
    return PBKDF2(password, salt, dkLen=32, count=iterations)

def main():
    password = input("Enter a password: ")
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)
    
    print(f"Salt: {base64.b64encode(salt).decode()}")
    print(f"Derived Key: {base64.b64encode(key).decode()}")

if __name__ == "__main__":
    main()
