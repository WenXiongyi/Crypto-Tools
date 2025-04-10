from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def process_key(key, required_length):
    """处理密钥，确保长度正确"""
    if not key:
        raise ValueError("密钥不能为空")
    key_bytes = key.encode() if isinstance(key, str) else key
    if len(key_bytes) < required_length:
        return key_bytes.ljust(required_length, b'\0')
    return key_bytes[:required_length]

def encrypt(key, plaintext):
    """AES加密"""
    key = process_key(key, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(key, ciphertext):
    """AES解密"""
    key = process_key(key, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted_plaintext.decode('utf-8') 