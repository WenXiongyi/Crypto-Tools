from ecdsa import NIST192p, SigningKey, VerifyingKey, BadSignatureError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import struct

def generate_key():
    """生成ECC密钥对"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    # 序列化私钥
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # 序列化公钥
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return {'privatekey': private_pem, 'publickey': public_pem}

def encrypt(public_key, plaintext):
    """ECC加密"""
    # 反序列化公钥
    public_key = serialization.load_pem_public_key(
        public_key.encode(),
        backend=default_backend()
    )
    
    # 生成临时密钥对
    ephemeral_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # ECDH密钥交换
    shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)
    
    # 派生加密密钥
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecies-v1',
        backend=default_backend()
    ).derive(shared_key)
    
    # AES-GCM加密
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    # 序列化临时公钥
    ephemeral_pub_bytes = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 合并所有组件
    merged = (
        struct.pack('>I', len(ephemeral_pub_bytes)) +
        ephemeral_pub_bytes +
        iv +
        encryptor.tag +
        ciphertext
    )
    
    return merged.hex()

def decrypt(private_key, merged_ciphertext):
    """ECC解密"""
    # 反序列化私钥
    private_key = serialization.load_pem_private_key(
        private_key.encode(),
        password=None,
        backend=default_backend()
    )
    
    # 将十六进制字符串转换为字节
    merged_ciphertext = bytes.fromhex(merged_ciphertext)
    
    # 解析字节流
    ptr = 0
    
    # 读取临时公钥长度
    pubkey_len = struct.unpack('>I', merged_ciphertext[ptr:ptr + 4])[0]
    ptr += 4
    
    # 提取临时公钥
    ephemeral_pub_bytes = merged_ciphertext[ptr:ptr + pubkey_len]
    ptr += pubkey_len
    
    # 加载临时公钥
    ephemeral_pub = serialization.load_pem_public_key(
        ephemeral_pub_bytes,
        backend=default_backend()
    )
    
    # 提取固定长度组件
    iv = merged_ciphertext[ptr:ptr + 12]
    ptr += 12
    tag = merged_ciphertext[ptr:ptr + 16]
    ptr += 16
    
    # 剩余部分是密文
    ciphertext = merged_ciphertext[ptr:]
    
    # ECDH密钥交换
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_pub)
    
    # 派生密钥
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecies-v1',
        backend=default_backend()
    ).derive(shared_key)
    
    # AES-GCM解密
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted.decode('utf-8')

def generate_ecdsa_key():
    """生成ECDSA密钥对"""
    sk = SigningKey.generate(curve=NIST192p)
    vk = sk.get_verifying_key()
    
    # 序列化私钥
    private_key = sk.to_string().hex()
    
    # 序列化公钥
    public_key = vk.to_string().hex()
    
    return {'privatekey': private_key, 'publickey': public_key}

def ecdsa_sign(private_key, plaintext):
    """ECDSA签名"""
    try:
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=NIST192p)
        signature = sk.sign(plaintext.encode())
        return signature.hex()
    except Exception as e:
        raise ValueError(f"ECDSA签名失败: {str(e)}")

def ecdsa_verify(public_key, plaintext, signature):
    """ECDSA验证"""
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=NIST192p)
        vk.verify(bytes.fromhex(signature), plaintext.encode())
        return 'valid'
    except BadSignatureError:
        return 'invalid'
    except Exception as e:
        if "Invalid signature" in str(e):
            return 'invalid'
        raise ValueError(f"ECDSA验证失败: {str(e)}") 