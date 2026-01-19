# Abstract

A message script written in Python for unsecure methods. Contains 3 modules: 

- Key Creation 
- Key Exchange
- Message Encryption

# Flow

This project uses both public key encryption with AES symmetric encryption to achieve a safe end to end communication with another user. 

Fundementally we have this situation: 

[User 1] Wants to send a message securely to [User 2] 

- [User 1] initiates a hello with [User 2]
- [User 2] sends [User 1] a public key while storing securely it's own private key
- [User 1] will use the public key to encrypt the symmetric key it's using to cipher its data
- [User 1] sends the encrypted data and key to [User 2]
- [User 2] decrypts this information using the private key

All of this will be done over a simple HTTP server in an effort to simulate an unsecure network.   

# Resources 

https://www.geeksforgeeks.org/computer-networks/advanced-encryption-standard-aes/
https://www.geeksforgeeks.org/computer-networks/public-key-encryption/

## Information for cryptography
https://cryptography.io/en/latest/