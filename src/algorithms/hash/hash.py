from Crypto.Hash import SHA3_256, RIPEMD160, HMAC, SHA1, SHA256
from Crypto.Protocol.KDF import PBKDF2
import hashlib

def sha1_hash(data):
    """SHA1哈希
    
    Args:
        data: 要哈希的数据，字符串或字节
    Returns:
        哈希值，十六进制字符串
    """
    if not data:
        raise ValueError("输入数据不能为空")
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = SHA1.new(data)
        return h.hexdigest()
    except Exception as e:
        raise ValueError(f"SHA1哈希失败: {str(e)}")

def sha256_hash(data):
    """SHA256哈希
    
    Args:
        data: 要哈希的数据，字符串或字节
    Returns:
        哈希值，十六进制字符串
    """
    if not data:
        raise ValueError("输入数据不能为空")
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = SHA256.new(data)
        return h.hexdigest()
    except Exception as e:
        raise ValueError(f"SHA256哈希失败: {str(e)}")

def sha3_hash(data):
    """SHA3-256哈希
    
    Args:
        data: 要哈希的数据，字符串或字节
    Returns:
        哈希值，十六进制字符串
    """
    if not data:
        raise ValueError("输入数据不能为空")
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = SHA3_256.new(data)
        return h.hexdigest()
    except Exception as e:
        raise ValueError(f"SHA3哈希失败: {str(e)}")

def ripemd160_hash(data):
    """RIPEMD160哈希
    
    Args:
        data: 要哈希的数据，字符串或字节
    Returns:
        哈希值，十六进制字符串
    """
    if not data:
        raise ValueError("输入数据不能为空")
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = RIPEMD160.new(data)
        return h.hexdigest()
    except Exception as e:
        raise ValueError(f"RIPEMD160哈希失败: {str(e)}")

def hmac_sha1(key, data):
    """HMAC-SHA1哈希
    
    Args:
        key: 密钥，字符串或字节
        data: 要哈希的数据，字符串或字节
    Returns:
        哈希值，十六进制字符串
    """
    if not key or not data:
        raise ValueError("密钥和数据都不能为空")
    try:
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = HMAC.new(key, data, digestmod=SHA1)
        return h.hexdigest()
    except Exception as e:
        raise ValueError(f"HMAC-SHA1哈希失败: {str(e)}")

def hmac_sha256(key, data):
    """HMAC-SHA256哈希
    
    Args:
        key: 密钥，字符串或字节
        data: 要哈希的数据，字符串或字节
    Returns:
        哈希值，十六进制字符串
    """
    if not key or not data:
        raise ValueError("密钥和数据都不能为空")
    try:
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(data, str):
            data = data.encode('utf-8')
        h = HMAC.new(key, data, digestmod=SHA256)
        return h.hexdigest()
    except Exception as e:
        raise ValueError(f"HMAC-SHA256哈希失败: {str(e)}")

def pbkdf2_derive(password, salt, iterations=10000, key_length=32):
    """PBKDF2密钥派生
    
    Args:
        password: 密码，字符串或字节
        salt: 盐值，字符串或字节
        iterations: 迭代次数，默认10000
        key_length: 派生密钥长度，默认32字节
    Returns:
        派生密钥，十六进制字符串
    """
    if not password or not salt:
        raise ValueError("密码和盐值都不能为空")
    try:
        if isinstance(password, str):
            password = password.encode('utf-8')
        if isinstance(salt, str):
            salt = salt.encode('utf-8')
        key = PBKDF2(password, salt, dkLen=key_length, count=iterations)
        return key.hex()
    except Exception as e:
        raise ValueError(f"PBKDF2派生失败: {str(e)}") 