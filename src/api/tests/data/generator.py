import os
import random
import string
import base64
import hashlib
from typing import Dict, Any

def generate_random_string(length: int) -> str:
    """生成随机字符串"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_aes_test_data() -> Dict[str, Any]:
    """生成AES测试数据"""
    key = generate_random_string(16)  # 16字节密钥
    plaintext = generate_random_string(32)
    ciphertext = base64.b64encode(plaintext.encode()).decode()  # 模拟加密结果
    
    return {
        "key": key,
        "plaintext": plaintext,
        "ciphertext": ciphertext
    }

def generate_rsa_test_data() -> Dict[str, Any]:
    """生成RSA测试数据"""
    public_key = generate_random_string(128)
    private_key = generate_random_string(128)
    plaintext = generate_random_string(32)
    signature = base64.b64encode(plaintext.encode()).decode()  # 模拟签名结果
    
    return {
        "public_key": public_key,
        "private_key": private_key,
        "plaintext": plaintext,
        "signature": signature
    }

def generate_hash_test_data() -> Dict[str, Any]:
    """生成哈希测试数据"""
    plaintext = generate_random_string(32)
    hash_value = hashlib.sha256(plaintext.encode()).hexdigest()
    
    return {
        "plaintext": plaintext,
        "hash": hash_value
    }

def generate_all_test_data() -> Dict[str, Any]:
    """生成所有测试数据"""
    return {
        "aes": generate_aes_test_data(),
        "rsa": generate_rsa_test_data(),
        "sha256": generate_hash_test_data()
    }

def save_generated_test_data(data: Dict[str, Any]):
    """保存生成的测试数据"""
    from .loader import save_all_test_data
    save_all_test_data(data)

def generate_and_save_test_data():
    """生成并保存测试数据"""
    data = generate_all_test_data()
    save_generated_test_data(data)
    return data

def update_test_data():
    """更新测试数据"""
    from .loader import load_all_test_data, save_all_test_data
    
    # 加载现有数据
    data = load_all_test_data()
    
    # 更新AES数据
    if "aes" in data:
        data["aes"] = generate_aes_test_data()
    
    # 更新RSA数据
    if "rsa" in data:
        data["rsa"] = generate_rsa_test_data()
    
    # 更新哈希数据
    if "sha256" in data:
        data["sha256"] = generate_hash_test_data()
    
    # 保存更新后的数据
    save_all_test_data(data)
    return data 