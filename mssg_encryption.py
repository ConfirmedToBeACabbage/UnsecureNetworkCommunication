from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# The Iv can be thought of as almost a salt. It's inserted with the plain text alongside the key
# into the algorithm to then get a random cipher each time. 

def EncryptMSSG(key, msg):
    iv = os.urandom(32)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(msg) + encryptor.finalize()
    return ct
    
def DecryptMSG(key, msg): 
    iv = os.urandom(32)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    ct = decryptor.update(msg) + decryptor.finalize()
    return ct 