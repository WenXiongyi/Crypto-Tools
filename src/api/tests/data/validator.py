import base64
import hashlib
from typing import Dict, Any, Optional

def validate_aes_data(data: Dict[str, Any]) -> bool:
    """验证AES测试数据"""
    required_fields = ['key', 'plaintext', 'ciphertext']
    
    # 检查必需字段
    if not all(field in data for field in required_fields):
        return False
    
    # 检查密钥长度
    if len(data['key']) != 16:
        return False
    
    # 检查密文格式
    try:
        base64.b64decode(data['ciphertext'])
    except:
        return False
    
    return True

def validate_rsa_data(data: Dict[str, Any]) -> bool:
    """验证RSA测试数据"""
    required_fields = ['public_key', 'private_key', 'plaintext', 'signature']
    
    # 检查必需字段
    if not all(field in data for field in required_fields):
        return False
    
    # 检查签名格式
    try:
        base64.b64decode(data['signature'])
    except:
        return False
    
    return True

def validate_hash_data(data: Dict[str, Any]) -> bool:
    """验证哈希测试数据"""
    required_fields = ['plaintext', 'hash']
    
    # 检查必需字段
    if not all(field in data for field in required_fields):
        return False
    
    # 检查哈希格式
    if len(data['hash']) != 64:  # SHA-256哈希长度为64
        return False
    
    return True

def validate_test_data(data: Dict[str, Any]) -> bool:
    """验证所有测试数据"""
    validators = {
        'aes': validate_aes_data,
        'rsa': validate_rsa_data,
        'sha256': validate_hash_data
    }
    
    # 检查每个算法的数据
    for algorithm, validator in validators.items():
        if algorithm in data:
            if not validator(data[algorithm]):
                return False
    
    return True

def get_validation_errors(data: Dict[str, Any]) -> Optional[str]:
    """获取验证错误信息"""
    if not validate_test_data(data):
        if 'aes' in data and not validate_aes_data(data['aes']):
            return "Invalid AES test data"
        if 'rsa' in data and not validate_rsa_data(data['rsa']):
            return "Invalid RSA test data"
        if 'sha256' in data and not validate_hash_data(data['sha256']):
            return "Invalid hash test data"
        return "Invalid test data format"
    return None

def fix_test_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """修复测试数据"""
    from .generator import (
        generate_aes_test_data,
        generate_rsa_test_data,
        generate_hash_test_data
    )
    
    fixed_data = data.copy()
    
    # 修复AES数据
    if 'aes' in data and not validate_aes_data(data['aes']):
        fixed_data['aes'] = generate_aes_test_data()
    
    # 修复RSA数据
    if 'rsa' in data and not validate_rsa_data(data['rsa']):
        fixed_data['rsa'] = generate_rsa_test_data()
    
    # 修复哈希数据
    if 'sha256' in data and not validate_hash_data(data['sha256']):
        fixed_data['sha256'] = generate_hash_test_data()
    
    return fixed_data 