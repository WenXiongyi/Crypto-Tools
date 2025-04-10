import hashlib
import hmac
from Crypto.Hash import SHA1, SHA256, SHA3_256, RIPEMD160
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def sha1_hash(plaintext):
    """SHA1哈希"""
    if not plaintext:
        raise ValueError("输入不能为空")
    try:
        return SHA1.new(plaintext.encode()).hexdigest()
    except Exception as e:
        raise ValueError(f"SHA1哈希计算失败: {str(e)}")

def sha256_hash(plaintext):
    """SHA256哈希"""
    if not plaintext:
        raise ValueError("输入不能为空")
    try:
        return hashlib.sha256(plaintext.encode()).hexdigest()
    except Exception as e:
        raise ValueError(f"SHA256哈希计算失败: {str(e)}")

def sha3_hash(plaintext):
    """SHA3哈希"""
    if not plaintext:
        raise ValueError("输入不能为空")
    try:
        return SHA3_256.new(plaintext.encode()).hexdigest()
    except Exception as e:
        raise ValueError(f"SHA3哈希计算失败: {str(e)}")

def ripemd160_hash(plaintext):
    """RIPEMD160哈希"""
    if not plaintext:
        raise ValueError("输入不能为空")
    try:
        return RIPEMD160.new(plaintext.encode()).hexdigest()
    except Exception as e:
        raise ValueError(f"RIPEMD160哈希计算失败: {str(e)}")

def hmac_sha1(key, plaintext):
    """HMAC-SHA1"""
    if not key or not plaintext:
        raise ValueError("密钥和输入都不能为空")
    try:
        return hmac.new(key.encode(), plaintext.encode(), hashlib.sha1).hexdigest()
    except Exception as e:
        raise ValueError(f"HMAC-SHA1计算失败: {str(e)}")

def hmac_sha256(key, plaintext):
    """HMAC-SHA256"""
    if not key or not plaintext:
        raise ValueError("密钥和输入都不能为空")
    try:
        return hmac.new(key.encode(), plaintext.encode(), hashlib.sha256).hexdigest()
    except Exception as e:
        raise ValueError(f"HMAC-SHA256计算失败: {str(e)}")

def pbkdf2_hash(plaintext, salt=None, iterations=10000):
    """PBKDF2
    
    Args:
        plaintext: 要哈希的文本
        salt: 盐值，如果不提供则随机生成
        iterations: 迭代次数，默认为10000
    """
    if not plaintext:
        raise ValueError("输入不能为空")
    try:
        if salt is None:
            salt = get_random_bytes(16)
        password = plaintext.encode('utf-8')
        return PBKDF2(password, salt, dkLen=32, count=iterations).hex()
    except Exception as e:
        raise ValueError(f"PBKDF2计算失败: {str(e)}") 