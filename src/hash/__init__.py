import hashlib
import hmac
from Crypto.Hash import SHA1, SHA256, SHA3_256, RIPEMD160
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def hash_algorithm(algorithm, plaintext):
    if algorithm == "SHA1":
        return SHA1.new(plaintext.encode()).hexdigest()
    elif algorithm == "SHA256":
        return hashlib.sha256(plaintext.encode()).hexdigest()
    elif algorithm == "SHA3":
        return SHA3_256.new(plaintext.encode()).hexdigest()
    elif algorithm == "RIPEMD160":
        return RIPEMD160.new(plaintext.encode()).hexdigest()
    elif algorithm == "HMACSHA1":
        key = plaintext  # Here you can assume plaintext is the key for HMAC
        return hmac.new(key.encode(), plaintext.encode(), hashlib.sha1).hexdigest()
    elif algorithm == "HMACSHA256":
        key = plaintext  # Here you can assume plaintext is the key for HMAC
        return hmac.new(key.encode(), plaintext.encode(), hashlib.sha256).hexdigest()
    elif algorithm == "PBKDF2":
        salt = get_random_bytes(16)  # Generate random salt
        return PBKDF2(plaintext, salt, dkLen=32).hex() 