import os 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Not using ED25519 because it's only for validating the signature of the message
#from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def CreateAESKey(): 
    key = os.urandom(16)
    return key 

def PerformHKDF(private_key, public_key): 
    shared_key = private_key.exchange(public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def CreatePublicPrivate(parameters_pass):
    
    if parameters_pass != {}: 
        parameters = parameters_pass
    else: 
        parameters = dh.generate_parameters(generator=2, key_size=2048)

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return private_key, public_key


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
    
    Generates an RSA public/private key pair.
    Returns:
        [public_key_pem_str, private_key_pem_str]


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
"""