import requests
import httpserver
# This is going to be the source file where we combine all packages to get a simple transaction working 

def demonstration():
    url = "http://localhost:8000/ping"
    
    # First we ping the fastapi
    response = requests.get(url)
    

if __name__ == "__main__":
    httpserver.beginserver() # We are starting the server
    demonstration()
