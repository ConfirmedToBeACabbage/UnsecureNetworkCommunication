from fastapi import FastAPI, Request 
import uvicorn

app = FastAPI()

# A pool of public keys that are associated with the client host ip 
publickeypool = {}

# A pool of private keys which are associated with the public keys
privatekeycorrelate = {}

# Method to remove the key 
def removekey(): 
    print("test")

# Using fast api as a quick http server with routes. This will be the receiving server.
@app.get("/ping")
def pingandpublic(req: Request): # Should private the public key back to the user
    publickeypool[req.client.host] = "Some public key" # This is the private key we're serving
    privatekeycorrelate["Some public key"] = "private key" # The correlation we're doing with the private and public key
    return {"message": "Thank you for the ping!" + req.client.host}

def beginserver(): 
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")