from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os, base64

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
    
    # We need to properly return this
    iv_ct = iv + ct 
    
    return base64.b64encode(iv_ct) #Encoded in base64

# There are some assumptions made here about this DecryptMSG
# We are receiving utf-8 decoded information
# So we should 
# 1) Decode the base64 information
# 2) Gather the iv that we assume is with 16 byte block padding
# 3) Get the rest of the ct message afterwards
def DecryptMSG(key, msg): 
    iv_ct = base64.b64decode(msg)

    iv = iv_ct[:16] 
    ct = iv_ct[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ct) + decryptor.finalize()

    # We should also make sure we remove the padding
    unpadding = padding.PKCS7(128).unpadder()
    final_data = unpadding.update(decrypted_data) + unpadding.finalize()

    return final_data 