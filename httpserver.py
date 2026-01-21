from fastapi import FastAPI, Request  # type: ignore
from key_creation import PerformHKDF, CreatePublicPrivate
from mssg_encryption import EncryptMSSG, DecryptMSG
from encodedecode import pubktopem, loadpubk
from logtofile import printtofile
import uvicorn, time, base64 # type: ignore

app = FastAPI()

private_key = ''
public_key = ''
session_key = ''


# Using fast api as a quick http server with routes. This will be the receiving server.
@app.get("/ping")
async def pingandpublic(req: Request): # Should private the public key back to the user
    global private_key, public_key, session_key

    printtofile("[SERVER] I received a hello from the client!")
    printtofile("[SERVER] I will make a public and private key!")

    # We received the ping, we generate a public and private key 
    privk, pubk = CreatePublicPrivate({})
    public_key = pubk # This is the public key we're serving
    private_key = privk 

    printtofile("[SERVER] I've made them and saved the private key")

    pubk = pubktopem(pubk)
    printtofile("[SERVER] Public Key: " + pubk.decode('utf-8'))
    
    # this is incase we have a session key, aka the second handshake
    if session_key != '': 
        printtofile("[SERVER] I already have a session_key with this client! I will use that as a layer of protection")
        pubk = EncryptMSSG(session_key, pubk)

    printtofile("[SERVER] Sending back the user this [public key]: " + pubk.decode('utf-8'))
    return {"pubk": pubk.decode('utf-8')} # We are always sending back a readable utf-8

@app.post("/public")
async def receivepublic(req: Request):
    global session_key, public_key

    printtofile("[SERVER] I received a public key from the client! This is still the handshake")
    printtofile("[SERVER] I need to decrypt (if we're using a session key) the public key and use HKDF to make a session key")

    # We have received the public key 
    body = await req.json()

    # Set the public key
    if session_key != '':
        printtofile("[SERVER] We have a session key! We will first decrypt the message and then retreive the pubk")
        public_key = loadpubk(DecryptMSG(session_key, body.get("pubk")))
    else:
        printtofile("[SERVER] We don't have a session key, we can just retreive the public key")
        public_key = loadpubk(body.get("pubk"))

    # Now that we have the public key we can perform the HKDF for a session key
    session_key = PerformHKDF(private_key, public_key)
    printtofile("[SERVER] Using the public key I got, I made a session_key. I assume it matches up because me and the client agree on parameters and our keys.")

    # Returning with a success!
    return {"message": "Success!"}


@app.post("/msg")
async def receivepublic(req: Request):
    global session_key

    printtofile("[SERVER] I received the msg route! This means, our channel is secure and I need to decrypt + decrypt the message with the symmetric key")

    # We have received the public key 
    body = await req.json()

    # Get the cipher keyy
    ekey = DecryptMSG(session_key, body.get("ekey"))
    emsg = DecryptMSG(session_key, body.get("emsg"))

    printtofile("[SERVER] Decrypting everything past the session_key ekey: " + base64.b64encode(ekey).decode('utf-8'))
    printtofile("[SERVER] Decrypting everything past the session_key emsg: " + base64.b64encode(emsg).decode('utf-8'))

    emsg = DecryptMSG(ekey, emsg)

    printtofile("[SERVER] Finally we can decrypt the message! msg: " + emsg.decode('utf-8'))

    # Returning with a success!
    return {"message": emsg.decode('utf-8')}


def beginserver(e): 
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
    while True: 
        if e.set(): 
            return
        time.sleep(5)
