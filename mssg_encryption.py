from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# The Iv can be thought of as almost a salt. It's inserted with the plain text alongside the key
# into the algorithm to then get a random cipher each time. 

def EncryptMSSG(key, msg):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(msg)
    padded_data += padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return ct
    
def DecryptMSG(key, msg): 
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(msg)
    data += unpadder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    ct = decryptor.update(data) + decryptor.finalize()
    return ct 