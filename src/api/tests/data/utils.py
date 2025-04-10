import json
import base64
import hashlib
from typing import Dict, Any, Optional

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

def format_json(data: Dict[str, Any], indent: int = 2) -> str:
    """格式化JSON数据"""
    return json.dumps(data, indent=indent)

def parse_json(data: str) -> Dict[str, Any]:
    """解析JSON数据"""
    return json.loads(data)

def merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """合并两个字典"""
    result = dict1.copy()
    result.update(dict2)
    return result

def filter_dict(data: Dict[str, Any], keys: list) -> Dict[str, Any]:
    """过滤字典，只保留指定的键"""
    return {k: v for k, v in data.items() if k in keys}

def exclude_dict(data: Dict[str, Any], keys: list) -> Dict[str, Any]:
    """过滤字典，排除指定的键"""
    return {k: v for k, v in data.items() if k not in keys}

def deep_update_dict(target: Dict[str, Any], source: Dict[str, Any]) -> Dict[str, Any]:
    """深度更新字典"""
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(value, dict):
            deep_update_dict(target[key], value)
        else:
            target[key] = value
    return target

def get_nested_value(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    """获取嵌套字典中的值"""
    keys = path.split('.')
    result = data
    for key in keys:
        if isinstance(result, dict) and key in result:
            result = result[key]
        else:
            return default
    return result

def set_nested_value(data: Dict[str, Any], path: str, value: Any) -> Dict[str, Any]:
    """设置嵌套字典中的值"""
    keys = path.split('.')
    result = data
    for key in keys[:-1]:
        if key not in result:
            result[key] = {}
        result = result[key]
    result[keys[-1]] = value
    return data

def remove_nested_value(data: Dict[str, Any], path: str) -> Dict[str, Any]:
    """删除嵌套字典中的值"""
    keys = path.split('.')
    result = data
    for key in keys[:-1]:
        if key not in result:
            return data
        result = result[key]
    if keys[-1] in result:
        del result[keys[-1]]
    return data 