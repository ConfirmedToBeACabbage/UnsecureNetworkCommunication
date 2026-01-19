import requests
import httpserver
# This is going to be the source file where we combine all packages to get a simple transaction working 

def demonstration():
    url = "http://localhost:8000/ping"
    
    # First we ping the fastapi
    response = requests.get(url)
    
    """
    TODO 
    
    (1) Response should return a public key (like a ssl certificate for analogy) and the server keeps the private key
    (2) Client generates a cipher 
    (3) Encrypt cipher with public key 
    (4) Send cipher to server
    (5) Server decrypts the msg with private key and saves the cipher
    (6) Client uses cipher to encrypt the msg 
    (7) Client encrypts with public key the msg on top of the cipher
    (8) Client sends server the msg 
    (9) Server receives, decrypts with private key and then uses cipher to decrypt msg 
     
     
     Method for development: 
     
     - Key_creation has methods which
        def CreateAESKey() (This creates a cipher key)
        def CreatePublicPrivate() (This creates a public key and a mathematically associated private key)
        
     - mssg_encryption has methods which
        def EncryptMSSG(cipher: Cipher, msg) (Takes in a cipher of class Cipher from the cryptography package), this encrypts a message using a cipher
        def DecryptMSG(cipher: Cipher, msg) (Takes in a cipher of class Cipher from the cryptography package), this decrypts a message using the cipher
    """ 
    
    
    

if __name__ == "__main__":
    httpserver.beginserver() # We are starting the server
    demonstration()
