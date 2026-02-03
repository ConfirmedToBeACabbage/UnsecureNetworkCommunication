import requests, threading, time, asyncio, base64
from httpserver import beginserver
from key_creation import CreateAESKey, PerformHKDF, CreatePublicPrivate
from mssg_encryption import EncryptMSSG, DecryptMSG
from encodedecode import pubktopem, loadpubk
from logtofile import initfilesend, printtofile
from key_manager import Capability, KeyManager 
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

async def handshake(manager: KeyManager, root_capability: Capability, demonstration_step: int): 
    global private_key, public_key, parameters
    url = "http://localhost:8000/ping"
    
    # First we ping the fastapi
    response = requests.get(url)

    # We receive the public key 
    convert = response.json()
    if demonstration_step >= 1: 
        public_key = loadpubk(DecryptMSG(manager.get_active_dek(manager.load_keyring("supersecretpassword", root_capability), root_capability), convert["pubk"])) # We are storing the public key 
    else: 
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

    # if session_key != '':
    #     pubk = EncryptMSSG(session_key, pubk)
    # So now instead of us just making the session key, we use the key manager to make a ring, store it and then retrieve it later.
    # We also can use the manager to rotate the key if required. So we always technically have a key.
    try: 
        manager.init_keyring_with_header("supersecretpassword", PerformHKDF(private_key, public_key), root_capability, "client_key_1") # Here we are storing a session key
    except FileExistsError as e: # However if the file already exists, that means we simply need to rotate them
        printtofile("[CLIENT] Keyring already exists. Continuing...")
        
        # Demonstrate that rotation will not let us read the old information
        printtofile("[CLIENT] Rotating keys for forward secrecy demonstration.")
        printtofile("[CLIENT] Getting the old key ring to show that we won't be able to extract the dek after rotation.")
        old_keyring = manager.load_keyring("supersecretpassword", root_capability)

        manager.rotate_key(manager.load_keyring("supersecretpassword", root_capability), root_capability, PerformHKDF(private_key, public_key), "client_key_2")
        
        printtofile("[CLIENT] Attempting to get the old DEK after rotation, it won't be able to")
        manager.get_active_dek(old_keyring, root_capability) 

    # Sending a post request with the public keyy
    if(demonstration_step >= 1): 
        pubk = EncryptMSSG(manager.get_active_dek(manager.load_keyring("supersecretpassword", root_capability), root_capability), pubk)

    response = requests.post(url, json={"pubk": pubk.decode('utf-8')})

    # Now that we've sent the post, we can generate on our end the session key
    #session_key = PerformHKDF(private_key, public_key)


async def demonstration(manager: KeyManager, root_capability: Capability):
    global private_key, public_key, parameters, e

    printtofile("[CLIENT] I want to start my first handshake with the server!")
    # Do one handshake
    await handshake(manager, root_capability, 0)

    printtofile("[CLIENT] Doing my second handshake with the server for forward secrecy!")
    # However now that we've done this once 
    # For forward secrecy we do it again with the session key
    await handshake(manager, root_capability, 1)

    # This is for demonstration of old information
    await handshake(manager, root_capability, 2)
    
    printtofile("[CLIENT] With forward secrecy established, we will now encrypt a message over the secure channel")

    # Session keys when are made with HKDF can't simply just be translated
    # to HKDF. They don't have the right start byte which tells us the length of the characters

    # Now that we have forward secrecy and everything established, we can do the cipher send
    mssg = b"Hello! This is a sample message I want to send :)"

    # Create a cipher and a key
    key = CreateAESKey()

    printtofile("[CLIENT] Key: " + base64.b64encode(key).decode('utf-8'))
    
    # Encrypt using the aes key we came up with
    emsg = EncryptMSSG(key, mssg)

    printtofile("[CLIENT] Encrypted Key: " + emsg.decode('utf-8'))
    printtofile("[CLIENT] We now will encrypt everything with our session key! I would output it, but the format of HKDF doens't support utf-8 conversions")

    # We now encrypt it with the session_key on top of all of that
    #ekey = EncryptMSSG(session_key, key) 
    #emsg = EncryptMSSG(session_key, emsg)
    ekey = EncryptMSSG(manager.get_active_dek(manager.load_keyring("supersecretpassword", root_capability), root_capability), key)
    emsg = EncryptMSSG(manager.get_active_dek(manager.load_keyring("supersecretpassword", root_capability), root_capability), emsg)

    # Simulation of wrong access role
    fake_capability = Capability(role="unauthorized_role")
    try: 
        ekey = EncryptMSSG(manager.get_active_dek(manager.load_keyring("supersecretpassword", fake_capability), fake_capability), key)
    except PermissionError as pe:
        printtofile("[CLIENT] Permission Error Caught Successfully: " + str(pe))   
    finally:
        printtofile("[CLIENT] Continuing...")

    printtofile("[CLIENT] Encrypted key (with session key): " + ekey.decode('utf-8'))
    printtofile("[CLIENT] Encrypted message (with session key): " + emsg.decode('utf-8'))
    printtofile("[CLIENT] Sending this over to the server!")

    # Send this information over
    url = "http://localhost:8000/msg"
    response = requests.post(url, json={"ekey": ekey.decode('utf-8'), "emsg": emsg.decode('utf-8')})

    convert = response.json()
    printtofile("[CLIENT] Final Message back! " + convert['message'])

    # End the server
    e.set()

parameters = {}
private_key = ''
public_key = ''
session_key = ''
e = threading.Event()

if __name__ == "__main__":

    # We should initiate the Keymanager with Capabilities Role + Master Key 
    #derive_master_key(b"SuperSecretPassword", b"UniqueSaltValue") <-- This is what we will pass in when we want to derive the master key, not stored on disk though
    key_manager = KeyManager()    
    root_capability = Capability(role="crypto_service")

    # Init the file for output
    initfilesend()

    # We should start the server on a seperate thread
    t1 = threading.Thread(target=beginserver, args=(e,))
    t1.start()

    # Let the server start
    time.sleep(1)

    asyncio.run(demonstration(key_manager, root_capability))
