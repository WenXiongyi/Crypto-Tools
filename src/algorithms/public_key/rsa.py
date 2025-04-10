from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1, SHA256
import base64

def generate_key():
    """生成RSA密钥对
    
    Returns:
        dict: 包含私钥和公钥的字典
    """
    try:
        key = RSA.generate(1024)
        private_key = key.export_key('PEM').decode()
        public_key = key.publickey().export_key('PEM').decode()
        return {
            'privatekey': private_key,
            'publickey': public_key
        }
    except Exception as e:
        raise ValueError(f"RSA密钥生成失败: {str(e)}")

def encrypt(public_key, plaintext):
    """RSA加密
    
    Args:
        public_key: PEM格式的公钥
        plaintext: 要加密的文本
    Returns:
        加密后的密文，Base64编码的字符串
    """
    # 检查输入
    if not plaintext:
        raise ValueError("明文不能为空")
    if not public_key:
        raise ValueError("公钥不能为空")
        
    try:
        # 加载公钥
        key = RSA.import_key(public_key)
        
        # 创建加密器
        cipher = PKCS1_OAEP.new(key)
        
        # 计算最大块大小
        max_length = key.size_in_bytes() - 42  # PKCS1_OAEP的填充需要42字节
        
        # 分块加密
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext_blocks = []
        
        for i in range(0, len(plaintext_bytes), max_length):
            block = plaintext_bytes[i:i + max_length]
            ciphertext_blocks.append(cipher.encrypt(block))
        
        # 合并所有块并Base64编码
        ciphertext = b''.join(ciphertext_blocks)
        return base64.b64encode(ciphertext).decode('utf-8')
    except (ValueError, IndexError, TypeError):
        raise ValueError("无效的公钥格式")
    except Exception as e:
        raise ValueError(f"RSA加密失败: {str(e)}")

def decrypt(private_key, ciphertext):
    """RSA解密
    
    Args:
        private_key: PEM格式的私钥
        ciphertext: Base64编码的密文
    Returns:
        解密后的明文，字符串
    """
    # 检查输入
    if not ciphertext:
        raise ValueError("密文不能为空")
    if not private_key:
        raise ValueError("私钥不能为空")
        
    try:
        # 加载私钥
        key = RSA.import_key(private_key)
        
        # 创建解密器
        cipher = PKCS1_OAEP.new(key)
        
        # Base64解码
        ciphertext_bytes = base64.b64decode(ciphertext)
        
        # 计算块大小
        block_size = key.size_in_bytes()
        
        # 分块解密
        plaintext_blocks = []
        
        for i in range(0, len(ciphertext_bytes), block_size):
            block = ciphertext_bytes[i:i + block_size]
            plaintext_blocks.append(cipher.decrypt(block))
        
        # 合并所有块并解码
        plaintext = b''.join(plaintext_blocks)
        return plaintext.decode('utf-8')
    except (ValueError, IndexError, TypeError):
        raise ValueError("无效的私钥格式")
    except Exception as e:
        raise ValueError(f"RSA解密失败: {str(e)}")

def sign(private_key, plaintext, hash_algorithm='sha1'):
    """RSA签名
    
    Args:
        private_key: PEM格式的私钥
        plaintext: 要签名的文本
        hash_algorithm: 哈希算法，可选'sha1'或'sha256'
    Returns:
        签名，Base64编码的字符串
    """
    # 检查输入
    if not plaintext:
        raise ValueError("明文不能为空")
    if not private_key:
        raise ValueError("私钥不能为空")
    if not hash_algorithm.lower() in ['sha1', 'sha256']:
        raise ValueError("不支持的哈希算法")
        
    try:
        # 加载私钥
        key = RSA.import_key(private_key)
        
        # 选择哈希算法
        if hash_algorithm.lower() == 'sha1':
            hash_obj = SHA1.new(plaintext.encode())
        else:
            hash_obj = SHA256.new(plaintext.encode())
        
        # 创建签名器
        signer = pkcs1_15.new(key)
        
        # 签名
        signature = signer.sign(hash_obj)
        
        # Base64编码
        return base64.b64encode(signature).decode('utf-8')
    except (ValueError, IndexError, TypeError):
        raise ValueError("无效的私钥格式")
    except Exception as e:
        raise ValueError(f"RSA签名失败: {str(e)}")

def verify(public_key, plaintext, signature, hash_algorithm='sha1'):
    """RSA验证
    
    Args:
        public_key: PEM格式的公钥
        plaintext: 原始文本
        signature: Base64编码的签名
        hash_algorithm: 哈希算法，可选'sha1'或'sha256'
    Returns:
        'valid'或'invalid'
    """
    # 检查输入
    if not plaintext:
        raise ValueError("明文不能为空")
    if not signature:
        raise ValueError("签名不能为空")
    if not public_key:
        raise ValueError("公钥不能为空")
    if not hash_algorithm.lower() in ['sha1', 'sha256']:
        raise ValueError("不支持的哈希算法")
        
    try:
        # 加载公钥
        key = RSA.import_key(public_key)
        
        # 选择哈希算法
        if hash_algorithm.lower() == 'sha1':
            hash_obj = SHA1.new(plaintext.encode())
        else:
            hash_obj = SHA256.new(plaintext.encode())
        
        # 创建验证器
        verifier = pkcs1_15.new(key)
        
        # Base64解码
        signature = base64.b64decode(signature)
        
        # 验证
        verifier.verify(hash_obj, signature)
        return 'valid'
    except (ValueError, IndexError, TypeError) as e:
        if str(e) == "Invalid signature":
            return 'invalid'
        raise ValueError("无效的公钥格式")
    except Exception as e:
        raise ValueError(f"RSA验证失败: {str(e)}") 