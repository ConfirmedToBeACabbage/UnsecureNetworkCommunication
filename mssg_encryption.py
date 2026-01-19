from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def EncryptMSSG(cipher: Cipher, msg):
    encryptor = cipher.encryptor()
    ct = encryptor.update(msg) + encryptor.finalize()
    
def DecryptMSG(cipher: Cipher, msg): 
    decryptor = cipher.decryptor()
    ct = decryptor.update(msg) + decryptor.finalize()
    return ct 