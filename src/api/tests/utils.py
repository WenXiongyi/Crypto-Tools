import json
import base64
import hashlib
from typing import Dict, Any, Optional
from ..schemas import (
    EncryptRequest, DecryptRequest, HashRequest,
    GenerateKeyRequest, SignRequest, VerifyRequest
)

def create_test_request(
    request_type: str,
    algorithm: str,
    **kwargs
) -> Dict[str, Any]:
    """创建测试请求数据"""
    request_classes = {
        'encrypt': EncryptRequest,
        'decrypt': DecryptRequest,
        'hash': HashRequest,
        'generate': GenerateKeyRequest,
        'sign': SignRequest,
        'verify': VerifyRequest
    }
    
    if request_type not in request_classes:
        raise ValueError(f"Invalid request type: {request_type}")
    
    request_class = request_classes[request_type]
    request_data = {
        "algorithm": algorithm,
        **kwargs
    }
    
    return request_class(**request_data).dict()

def create_test_response(
    success: bool,
    code: int,
    data: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None
) -> Dict[str, Any]:
    """创建测试响应数据"""
    response = {
        "success": success,
        "code": code
    }
    
    if data is not None:
        response["data"] = data
    
    if error is not None:
        response["error"] = error
    
    return response

def encode_base64(data: str) -> str:
    """Base64编码"""
    return base64.b64encode(data.encode()).decode()

def decode_base64(data: str) -> str:
    """Base64解码"""
    return base64.b64decode(data.encode()).decode()

def calculate_hash(data: str, algorithm: str = 'sha256') -> str:
    """计算哈希值"""
    hash_func = getattr(hashlib, algorithm)
    return hash_func(data.encode()).hexdigest()

def validate_response(
    response_data: Dict[str, Any],
    expected_success: bool,
    expected_code: int,
    expected_data_keys: Optional[list] = None,
    expected_error: Optional[str] = None
) -> bool:
    """验证响应数据"""
    if response_data.get('success') != expected_success:
        return False
    
    if response_data.get('code') != expected_code:
        return False
    
    if expected_data_keys is not None:
        data = response_data.get('data', {})
        if not all(key in data for key in expected_data_keys):
            return False
    
    if expected_error is not None:
        if response_data.get('error') != expected_error:
            return False
    
    return True

def load_test_data(file_path: str) -> Dict[str, Any]:
    """加载测试数据"""
    with open(file_path, 'r') as f:
        return json.load(f)

def save_test_data(file_path: str, data: Dict[str, Any]):
    """保存测试数据"""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

def create_test_logger(name: str):
    """创建测试日志记录器"""
    import logging
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    
    # 创建格式化器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    
    # 添加处理器
    logger.addHandler(console_handler)
    
    return logger 