from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class CryptoAlgorithm(ABC):
    """密码算法基类"""
    
    @abstractmethod
    def __init__(self, **kwargs):
        """初始化算法"""
        pass
    
    @abstractmethod
    def validate_params(self, **kwargs) -> bool:
        """验证参数"""
        pass
    
    @abstractmethod
    def process(self, **kwargs) -> Dict[str, Any]:
        """处理数据"""
        pass

class SymmetricCrypto(CryptoAlgorithm):
    """对称加密基类"""
    
    @abstractmethod
    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """加密"""
        pass
    
    @abstractmethod
    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """解密"""
        pass

class AsymmetricCrypto(CryptoAlgorithm):
    """非对称加密基类"""
    
    @abstractmethod
    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        """加密"""
        pass
    
    @abstractmethod
    def decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """解密"""
        pass

class HashAlgorithm(CryptoAlgorithm):
    """哈希算法基类"""
    
    @abstractmethod
    def hash(self, data: bytes) -> bytes:
        """计算哈希"""
        pass

class SignatureAlgorithm(CryptoAlgorithm):
    """签名算法基类"""
    
    @abstractmethod
    def sign(self, private_key: bytes, data: bytes) -> bytes:
        """签名"""
        pass
    
    @abstractmethod
    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """验证签名"""
        pass

class KeyManager(CryptoAlgorithm):
    """密钥管理基类"""
    
    @abstractmethod
    def generate_key(self, **kwargs) -> Dict[str, bytes]:
        """生成密钥"""
        pass
    
    @abstractmethod
    def import_key(self, key_data: bytes) -> Dict[str, bytes]:
        """导入密钥"""
        pass
    
    @abstractmethod
    def export_key(self, key: bytes) -> bytes:
        """导出密钥"""
        pass 