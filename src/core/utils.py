import base64
import hashlib
import logging
from typing import Union, Dict, Any
from .exceptions import CryptoError

def setup_logger(name: str) -> logging.Logger:
    """设置日志记录器"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 文件处理器
    file_handler = logging.FileHandler(f'{name}.log')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

def base64_encode(data: bytes) -> str:
    """Base64编码"""
    return base64.b64encode(data).decode('utf-8')

def base64_decode(data: str) -> bytes:
    """Base64解码"""
    try:
        return base64.b64decode(data)
    except Exception as e:
        raise CryptoError(f"Base64 decode failed: {str(e)}")

def validate_key_length(key: bytes, expected_length: int) -> None:
    """验证密钥长度"""
    if len(key) != expected_length:
        raise CryptoError(
            f"Invalid key length: expected {expected_length} bytes, got {len(key)} bytes"
        )

def pad_data(data: bytes, block_size: int) -> bytes:
    """PKCS7填充"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad_data(data: bytes) -> bytes:
    """PKCS7去填充"""
    padding_length = data[-1]
    if padding_length > len(data):
        raise CryptoError("Invalid padding")
    return data[:-padding_length]

def create_response(
    success: bool,
    data: Union[Dict[str, Any], None] = None,
    error: Union[str, None] = None,
    code: int = 200
) -> Dict[str, Any]:
    """创建统一响应格式"""
    response = {
        "success": success,
        "code": code
    }
    
    if data is not None:
        response["data"] = data
    
    if error is not None:
        response["error"] = error
    
    return response

def hash_data(data: bytes, algorithm: str = 'sha256') -> bytes:
    """计算数据的哈希值"""
    try:
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data)
        return hash_obj.digest()
    except Exception as e:
        raise CryptoError(f"Hash computation failed: {str(e)}") 