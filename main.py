import requests, threading, time, asyncio
from httpserver import beginserver
from key_creation import CreateAESKey, PerformHKDF, CreatePublicPrivate
from mssg_encryption import EncryptMSSG
from encodedecode import encodeaesk, pubktopem, loadpubk
from logtofile import initfilesend, printtofile
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

Repeat this process again! Using the session key provided. 

The session is now secured with foward secrecy. This is because each side generates a shared session using a public key associated with the other side. 
Man in the middle can hurt this process. However this is where certificate authorities (CA) come into use. You can confirm the authenticity of the certificate with an authority. 

(3) Encrypt a message with a key
(4) Send that message to the server alongside the key, on the new session key
(5) Decrypt on the server and present it as proof! 
""" 

parameters = {}
private_key = ''
public_key = ''
session_key = ''

async def handshake(): 
    global private_key, public_key, session_key, parameters
    url = "http://localhost:8000/ping"
    
    # First we ping the fastapi
    printtofile("[CLIENT] REQUESTING SERVER FOR HANDSHAKE BEGIN")
    response = requests.get(url)

    # We receive the public key 
    convert = response.json()
    public_key = loadpubk(convert["pubk"]) # We are storing the public key 
    parameters = public_key.parameters()
    printtofile("[CLIENT] Public Key: " + convert["pubk"])

    # Generate the private and public key
    privk, pubk = CreatePublicPrivate(parameters)

    # Encode the public key in a format that works
    pubk = pubktopem(pubk)

    # Storing the private key
    private_key = privk
    printtofile("[CLIENT] Private Key Saved!")

    # Send back the server the public key
    url = "http://localhost:8000/public"

    if session_key != '':
        pubk = EncryptMSSG(session_key, pubk)

    # Sending a post request with the public keyy
    response = requests.post(url, json={"pubk": pubk.decode('utf-8')})

    # Now that we've sent the post, we can generate on our end the session key
    session_key = PerformHKDF(private_key, public_key)

async def demonstration():
    global private_key, public_key, session_key, parameters
    printtofile("[CLIENT] Beginning a handshake!")
    # Do one handshake
    await handshake()

    printtofile("[CLIENT] Doing DH twice for forward secrecy")
    # However now that we've done this once 
    # For forward secrecy we do it again with the session key
    await handshake()
    
    printtofile("[CLIENT] Now that we have a second session open, we will encrypt a message using AES and send it over")
    # Ensuring session_key is in bytes form
    session_key = session_key.encode('utf-8')

    printtofile("[CLIENT] Session Key: " + str(session_key))
    # Now that we have forward secrecy and everything established, we can do the cipher send
    mssg = b"Hello!"

    # Create a cipher and a key
    key = CreateAESKey()
    
    # Encrypt using the cipher
    emsg = EncryptMSSG(key, mssg)

    # We now encrypt it with the session key y
    ekey = EncryptMSSG(session_key, key)
    emsg = EncryptMSSG(session_key, emsg)
    
    ekey = encodeaesk(key)

    # Send this information over
    url = "http://localhost:8000/msg"
    response = requests.post(url, json={"ekey": ekey, "emsg": emsg})

    # End the server
    e.set()

if __name__ == "__main__":

    # Init the file for output
    initfilesend()

    # We should start the server on a seperate thread
    e = threading.Event()
    t1 = threading.Thread(target=beginserver, args=(e,))
    t1.start()

    # Let the server start
    time.sleep(1)

    asyncio.run(demonstration())
