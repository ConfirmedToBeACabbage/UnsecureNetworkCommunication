from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_parameters, Encoding, PublicFormat
import base64

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
def pubktopem(publickey):
    return publickey.public_bytes(encoding = Encoding.PEM, format = PublicFormat.SubjectPublicKeyInfo)

def loadpubk(pempublickey):
    if isinstance(pempublickey, str): 
        pempublickey = pempublickey.encode('utf-8')

    return load_pem_public_key(pempublickey)