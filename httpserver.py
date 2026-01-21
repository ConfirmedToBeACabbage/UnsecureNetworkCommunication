from fastapi import FastAPI, Request  # type: ignore
from key_creation import PerformHKDF, CreatePublicPrivate
from mssg_encryption import EncryptMSSG, DecryptMSG
from encodedecode import pubktopem, loadpubk, decodeaesk
from logtofile import printtofile
import uvicorn # type: ignore

app = FastAPI()

private_key = ''
public_key = ''
session_key = ''


# Using fast api as a quick http server with routes. This will be the receiving server.
@app.get("/ping")
async def pingandpublic(req: Request): # Should private the public key back to the user
    global private_key, public_key, session_key

    # We received the ping, we generate a public and private key 
    privk, pubk = CreatePublicPrivate({})
    parameters = privk.parameters()
    public_key = pubk # This is the public key we're serving
    private_key = privk 

    pubk = pubktopem(pubk)
    printtofile("[SERVER] Public Key: " + str(pubk))
    
    # this is incase we have a session key, aka the second handshake
    if session_key != '': 
        pubk = EncryptMSSG(session_key, pubk)

    return {"pubk": pubk.decode('utf-8')} # We are always sending back a readable utf-8

@app.post("/public")
async def receivepublic(req: Request):
    global session_key, public_key

    # We have received the public key 
    body = await req.json()

    # Set the public key
    public_key = loadpubk(body.get("pubk"))

    # Now that we have the public key we can perform the HKDF for a session key
    session_key = PerformHKDF(private_key, public_key)

    # Returning with a success!
    return {"message": "Success!"}


@app.post("/msg")
async def receivepublic(req: Request):
    global session_key

    # We have received the public key 
    body = await req.json()

    # Get the cipher keyy
    ekey = DecryptMSG(session_key, decodeaesk(body.get("ekey")))
    emsg = DecryptMSG(session_key, body.get("emsg"))
    emsg = DecryptMSG(ekey, emsg)

    # Returning with a success!
    return {"message": "Success!"}


def beginserver(e): 
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
    if e.set(): 
        return

