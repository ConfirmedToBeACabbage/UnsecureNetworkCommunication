# Abstract

A message script written in Python for unsecure methods. Contains 3 modules: 

- Key Creation 
- Key Exchange
- Message Encryption

# Flow

This is following the lab description + constraints that are put forward. The file structure of the
project is exactly how the lab is, however we’re confident that it will work well together in the end
when everything is explained.

The concept is simple:
  1. We have a client
  2. We have a server
  3. The client wants to talk to the server

What we need to do is use asymmetric encryption to have a secure session. AKA public private
keys. From there we need something more symmetric for the information itself. The very simple
flow of the communication is:

1. Client pings the server (Sort of like “Hello! I want to speak to you”)
- This is unsecure and where a well rooted man in the middle still renders all this useless to a degree
- This is with a caveat, since modern systems also incorporate ED25519 asymmetric encryption. This actually validates the messages being sent, so this can “beat” man in the middle.
- Certificate authorities which can mitigate poor man in the middle implementations which try to act like an authority

2. Server gets the message and responds to the user with a public key
- Server stores private key
3. Client receives the public key, derives the parameters that were used to make it
- Client creates a private key based on derived parameters
- This ensures that both client and server agree with each other
- Client creates a public key based on derived parameters
- This again ensures that both client and server agree with each other
4. Client sends the public key it created back to the server, while using HKDF with the public key from the server to make a session_key
5. The server receives the public key and on its end replicates the step of making a session_key

This is a single handshake. The session_key that they both derive is mathematically linked. So
it will work in encrypting the session and decrypting it

# Running Or Seeing Output

You can run this from a text editor like Visual Studio with the python extension. Put breakpoints in place to see how everything executes. 

Or look through the output.txt file which outputs the communication that happens between the client and server. 

# Resources 

https://www.geeksforgeeks.org/computer-networks/advanced-encryption-standard-aes/
https://www.geeksforgeeks.org/computer-networks/public-key-encryption/

## Information for cryptography
https://cryptography.io/en/latest/
