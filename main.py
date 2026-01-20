import requests
import httpserver
# This is going to be the source file where we combine all packages to get a simple transaction working 

   """
    Diffie-Hellman (DH)

    (1) Server receives a ping request
        - Generate a private key 
            - Generate a public key 

        Return a public key to client

    (2) Client receives the public key 
        - Generates a private key
            - Generates a public key 

        Return a public key to the server

    (3) Both the server and the client produce a shared session key using HKDF 
    
    The session is now secured with foward secrecy. This is because each side generates a shared session using a public key associated with the other side. 
    Man in the middle can hurt this process. However this is where certificate authorities (CA) come into use. You can confirm the authenticity of the certificate with an authority. 

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

parameters = NULL
private_key = ''
public_key = ''
session_key = ''

def handshake(): 
    url = "http://localhost:8000/ping"
    
    # First we ping the fastapi
    response = requests.get(url)

    # We receive the public key 
    convert = response.json()
    public_key = convert["pubk"] # We are storing the public key 
    parameters = convert["parameters"] # Storing the shared parameters

    # Generate the private and public key
    pubk, privk = CreatePublicPrivate(parameters)

    # Storing the private key
    private_key = privk

    # Send back the server the public key
    url = "http://localhost:8000/public"

    if session_key != '' { 
        pubk = EncryptMSSG(session_key, pubk)
    }

    # Sending a post request with the public keyy
    response = requests.post(url, json={"pubk": pubk})

    # Now that we've sent the post, we can generate on our end the session key
    session_key = PerformHKDF()

def demonstration():
    
    # Do one handshake
    handshake()

    # However now that we've done this once 
    # For forward secrecy we do it again with the session key
    handshake()

    # Now that we have forward secrecy and everything established, we can do the cipher send
    mssg = b"Hello!"

    # Create a cipher and a key
    key = CreateAESKey()

    # Encrypt using the cipher
    emsg = EncryptMSSG(key, mssg)

    # We now encrypt it with the session key y
    ekey = EncryptMSSG(session_key, key)
    emsg = EncryptMSSG(session_key, emsg)

    # Send this information over
    url = "http://localhost:8000/msg"
    response = requests.post(url, json={"ekey": ekey, "emsg": emsg})



    
    
    

if __name__ == "__main__":
    httpserver.beginserver() # We are starting the server
    demonstration()
