from .aes import aes_encrypt, aes_decrypt
from .sm4 import sm4_encrypt, sm4_decrypt
from .rc6 import rc6_encrypt, rc6_decrypt
from Crypto.Util.Padding import pad, unpad
import base64

def process_key(key, required_length):
    key_bytes = key.encode() if isinstance(key, str) else key
    if len(key_bytes) < required_length:
        return key_bytes.ljust(required_length, b'\0')
    return key_bytes[:required_length]

def symmetric_encrypt(algorithm, data):
    if algorithm == "AES":
        key = data.get('key')
        plaintext = data.get('plaintext')
        return aes_encrypt(key, plaintext)
    elif algorithm == "SM4":
        key = data.get('key')
        plaintext = data.get('plaintext')
        return sm4_encrypt(key, plaintext)
    elif algorithm == "RC6":
        key = data.get('key')
        plaintext = data.get('plaintext')
        return rc6_encrypt(key, plaintext)
    else:
        return "Unsupported algorithm"

def symmetric_decrypt(algorithm, data):
    if algorithm == "AES":
        key = data.get('key')
        ciphertext = base64.b64decode(data.get('ciphertext'))
        return aes_decrypt(key, ciphertext)
    elif algorithm == "SM4":
        key = data.get('key')
        ciphertext = data.get('ciphertext')
        return sm4_decrypt(key, ciphertext)
    elif algorithm == "RC6":
        key = data.get('key')
        ciphertext = data.get('ciphertext')
        return rc6_decrypt(key, ciphertext)
    else:
        return "Unsupported algorithm" 