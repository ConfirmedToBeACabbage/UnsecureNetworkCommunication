import os 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def CreateAESKey(): 
    key = os.urandom(32)
    iv = os.urandom(32)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher 

def CreatePublicPrivate(): 
    print("test")
"""
# ===============================
# KEY CREATION MODULE
# Author: Adakole
# Purpose:
# - Generate symmetric AES key (CreateAESKey)
# - Generate RSA public/private key pair (CreatePublicPrivate)
# Returns values only (no file I/O) so other modules can use them
# ===============================
def CreatePublicPrivate():
    """
    Generates an RSA public/private key pair.
    Returns:
        [public_key_pem_str, private_key_pem_str]
    """

    # Step 1: Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Step 2: Derive the corresponding public key
    public_key = private_key.public_key()

    # Step 3: Serialize private key to PEM string
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    # Step 4: Serialize public key to PEM string
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    

    # Step 5: Return as list so other modules can consume it
    return [public_pem, private_pem]
    
    def CreateAESKey():
    """
    Generates a random AES key and IV, then returns a Cipher object.
    Used for symmetric message encryption.
    """
    key = os.urandom(32)   # 256-bit AES key
    iv = os.urandom(16)    # AES block size
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher
"""
