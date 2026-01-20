from cryptography import serialization

'''
TODO 

    # Serialize the public key
    pub_key_serialized = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Send back
    "public_key": pub_key_serialized.decode('utf-8'),  # For response as a string

    # This is on the receiving end
    public_key = serialization.load_pem_public_key(
        pem_public_key_str.encode('utf-8')
    )

    # Encode in hex
    aes_key = aes_key.hex()

    # Then decode in hex
    aes_key = bytes.fromhex(encryption_request.aes_key)  # Convert from hex to bytes
'''

# Encoding and decoding the public key
def encodepubk(publickey): 
    return publickey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def decodepubk(serializedpublickkey):
    return serialization.load_pem_public_key(
        serializedpublickkey.encode('utf-8')
    )
    
# Encoding and decoding the aes key
def encodeaesk(aeskey):
    return aeskey.hex()

def decodeaesk(aeskeyhex):
    return bytes.fromhex(aeskeyhex)