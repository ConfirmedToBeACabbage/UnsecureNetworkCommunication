from fastapi import FastAPI, Request 
import uvicorn, logging
from key_creation import PerformHKDF, CreatePublicPrivate
from mssg_encryption import EncryptMSSG, DecryptMSG

app = FastAPI()

private_key = ''
public_key = ''
session_key = ''

logging.basicConfig(level=logging.INFO)  # Set the logging level
logger = logging.getLogger(__name__)  # Create a logger

# Using fast api as a quick http server with routes. This will be the receiving server.
@app.get("/ping")
async def pingandpublic(req: Request): # Should private the public key back to the user

    # We received the ping, we generate a public and private key 
    pubk, privk, parameters = CreatePublicPrivate({})
    public_key = pubk # This is the public key we're serving
    private_key = privk 
    logger.info("[SERVER] Public Key: " + public_key + " | Private Key: " + private_key + " | Parameters: " + parameters)
    
    # this is incase we have a session key, aka the second handshake
    if session_key != '': 
        pubk = EncryptMSSG(session_key, pubk)
        parameters = EncryptMSSG(session_key, parameters)

    return {"pubk": str(pubk), "parameters": str(parameters)}

@app.post("/public")
async def receivepublic(req: Request):

    # We have received the public key 
    body = await req.json()

    # Set the public key
    public_key = body.get("pubk")

    # Now that we have the public key we can perform the HKDF for a session key
    session_key = PerformHKDF()

    # Returning with a success!
    return {"message": "Success!"}


@app.post("/msg")
async def receivepublic(req: Request):

    # We have received the public key 
    body = await req.json()

    # Get the cipher keyy
    ekey = DecryptMSG(session_key, body.get("ekey"))
    emsg = DecryptMSG(session_key, body.get("emsg"))
    emsg = DecryptMSG(ekey, emsg)

    print("The cipher key: " + ekey + " | The message: " + emsg)

    # Returning with a success!
    return {"message": "Success!"}


def beginserver(e): 
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
    if e.set(): 
        return

