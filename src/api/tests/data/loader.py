import json
import os
from typing import Dict, Any

def load_test_data(file_path: str) -> Dict[str, Any]:
    """加载测试数据"""
    with open(file_path, 'r') as f:
        return json.load(f)

def save_test_data(file_path: str, data: Dict[str, Any]):
    """保存测试数据"""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

def get_test_data_path() -> str:
    """获取测试数据文件路径"""
    return os.path.join(os.path.dirname(__file__), 'test_data.json')

def load_all_test_data() -> Dict[str, Any]:
    """加载所有测试数据"""
    return load_test_data(get_test_data_path())

def save_all_test_data(data: Dict[str, Any]):
    """保存所有测试数据"""
    save_test_data(get_test_data_path(), data)

def get_test_data(algorithm: str) -> Dict[str, Any]:
    """获取指定算法的测试数据"""
    data = load_all_test_data()
    return data.get(algorithm, {})

def update_test_data(algorithm: str, new_data: Dict[str, Any]):
    """更新指定算法的测试数据"""
    data = load_all_test_data()
    data[algorithm] = new_data
    save_all_test_data(data)

def delete_test_data(algorithm: str):
    """删除指定算法的测试数据"""
    data = load_all_test_data()
    if algorithm in data:
        del data[algorithm]
        save_all_test_data(data)

def clear_test_data():
    """清空所有测试数据"""
    save_all_test_data({}) 