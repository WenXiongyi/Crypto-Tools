from gmssl import sm4
import base64

def process_key(key, required_length=16):
    """处理密钥，确保长度正确"""
    if key is None:
        raise ValueError("密钥不能为空")
    if isinstance(key, str):
        if not key.strip():
            raise ValueError("密钥不能为空")
        key_bytes = key.encode()
    else:
        if not key:
            raise ValueError("密钥不能为空")
        key_bytes = key
    if len(key_bytes) < required_length:
        return key_bytes.ljust(required_length, b'\0')
    return key_bytes[:required_length]

def encrypt(key, plaintext):
    """SM4加密
    
    Args:
        key: 密钥，16字节
        plaintext: 明文，字符串或字节
    Returns:
        加密后的密文，Base64编码的字符串
    """
    try:
        # 处理密钥
        key = process_key(key)
        
        # 处理明文
        if plaintext is None:
            raise ValueError("明文不能为空")
        if isinstance(plaintext, str):
            if not plaintext.strip():
                raise ValueError("明文不能为空")
            plaintext = plaintext.encode('utf-8')
        elif not plaintext:
            raise ValueError("明文不能为空")
            
        # 创建SM4对象
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
        
        # 加密
        ciphertext = crypt_sm4.crypt_ecb(plaintext)
        
        # Base64编码
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        raise ValueError(f"SM4加密失败: {str(e)}")

def decrypt(key, ciphertext):
    """SM4解密
    
    Args:
        key: 密钥，16字节
        ciphertext: 密文，Base64编码的字符串
    Returns:
        解密后的明文，字符串
    """
    try:
        # 处理密钥
        key = process_key(key)
        
        # Base64解码
        ciphertext = base64.b64decode(ciphertext)
        
        # 创建SM4对象
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
        
        # 解密
        plaintext = crypt_sm4.crypt_ecb(ciphertext)
        
        # 解码为字符串
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"SM4解密失败: {str(e)}") 