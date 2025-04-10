from gmssl import sm4
from . import process_key

def sm4_encrypt(key, plaintext):
    key = process_key(key, 16)
    sm4_crypt = sm4.CryptSM4()
    sm4_crypt.set_key(key, sm4.SM4_ENCRYPT)
    return sm4_crypt.crypt_ecb(plaintext.encode()).hex()

def sm4_decrypt(key, ciphertext):
    key = process_key(key, 16)
    ciphertext = bytes.fromhex(ciphertext)
    sm4_crypt = sm4.CryptSM4()
    sm4_crypt.set_key(key, sm4.SM4_DECRYPT)
    return sm4_crypt.crypt_ecb(ciphertext).decode() 