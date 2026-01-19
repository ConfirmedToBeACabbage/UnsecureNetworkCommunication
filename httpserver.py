from fastapi import FastAPI, Request 
import uvicorn

app = FastAPI()

# A pool that correlates the hostip to the message received (encrypted) msgpool[hostip] = msg
msgpool = {}

# A pool of public keys that are associated with the client host ip  publickeycorrelate[hostip] = publickey
publickeycorrelate = {}

# A pool of private keys which are associated with the public keys publicprivatecorrelate[public] = private 
publicprivatecorrelate = {}

# A pool which associates the privatekey with the cipher below it privateciphercorrelate[privatekey] = cipher
privateciphercorrelate = {}

# Method to remove the key 
def removekey(): 
    print("test")

# Using fast api as a quick http server with routes. This will be the receiving server.
@app.get("/ping")
def pingandpublic(req: Request): # Should private the public key back to the user
    publickeycorrelate[req.client.host] = "Some public key" # This is the private key we're serving
    publicprivatecorrelate["Some public key"] = "private key" # The correlation we're doing with the private and public key
    return {"message": "Thank you for the ping!" + req.client.host}

@app.get("/cipher") 
def receivecipher(req: Request): # Receive and store teh cipher
    return True 

@app.get("/mssg")
def receivemsg(req: Request): # Receive and store the msg
    return True 

def beginserver(): 
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")