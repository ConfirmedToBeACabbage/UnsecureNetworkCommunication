import os 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def CreateAESKey(): 
    key = os.urandom(32)
    iv = os.urandom(32)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher 

def CreatePublicPrivate(): 
    print("test")