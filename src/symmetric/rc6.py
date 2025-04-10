from base64 import b64encode, b64decode
from .rc6_encryption import RC6Encryption

def encrypt(key: str, plaintext: str) -> str:
    key_bytes = key.encode('utf-8')
    data_bytes = plaintext.encode('utf-8')
    
    rc6 = RC6Encryption(key_bytes)
    encrypted = rc6.encrypt(data_bytes)
    return b64encode(encrypted).decode('utf-8')

def decrypt(key: str, ciphertext: str) -> str:
    key_bytes = key.encode('utf-8')
    data_bytes = b64decode(ciphertext.encode('utf-8'))
    
    rc6 = RC6Encryption(key_bytes)
    decrypted = rc6.decrypt(data_bytes)
    return decrypted.decode('utf-8') 