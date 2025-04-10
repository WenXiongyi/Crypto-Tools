from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from . import process_key

def aes_encrypt(key, plaintext):
    key = process_key(key, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    return ciphertext_base64

def aes_decrypt(key, ciphertext):
    key = process_key(key, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_plaintext.decode('utf-8') 