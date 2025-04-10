from typing import Dict, Any, Optional
from .loader import (
    load_all_test_data,
    save_all_test_data,
    get_test_data,
    update_test_data as update_loader_test_data,
    delete_test_data,
    clear_test_data
)
from .generator import (
    generate_aes_test_data,
    generate_rsa_test_data,
    generate_hash_test_data,
    generate_all_test_data,
    update_test_data as update_generator_test_data
)
from .validator import (
    validate_test_data,
    get_validation_errors,
    fix_test_data
)

class TestDataManager:
    """测试数据管理器"""
    
    def __init__(self):
        """初始化测试数据管理器"""
        self._data = load_all_test_data()
    
    def load(self) -> Dict[str, Any]:
        """加载测试数据"""
        self._data = load_all_test_data()
        return self._data
    
    def save(self, data: Optional[Dict[str, Any]] = None):
        """保存测试数据"""
        if data is not None:
            self._data = data
        save_all_test_data(self._data)
    
    def get(self, algorithm: str) -> Dict[str, Any]:
        """获取指定算法的测试数据"""
        return get_test_data(algorithm)
    
    def update(self, algorithm: str, new_data: Dict[str, Any]):
        """更新指定算法的测试数据"""
        update_loader_test_data(algorithm, new_data)
        self._data = load_all_test_data()
    
    def delete(self, algorithm: str):
        """删除指定算法的测试数据"""
        delete_test_data(algorithm)
        self._data = load_all_test_data()
    
    def clear(self):
        """清空所有测试数据"""
        clear_test_data()
        self._data = {}
    
    def generate(self, algorithm: Optional[str] = None) -> Dict[str, Any]:
        """生成测试数据"""
        generators = {
            'aes': generate_aes_test_data,
            'rsa': generate_rsa_test_data,
            'sha256': generate_hash_test_data
        }
        
        if algorithm is None:
            data = generate_all_test_data()
        elif algorithm in generators:
            data = {algorithm: generators[algorithm]()}
        else:
            raise ValueError(f"Invalid algorithm: {algorithm}")
        
        self.save(data)
        return data
    
    def validate(self) -> bool:
        """验证测试数据"""
        return validate_test_data(self._data)
    
    def get_errors(self) -> Optional[str]:
        """获取验证错误信息"""
        return get_validation_errors(self._data)
    
    def fix(self) -> Dict[str, Any]:
        """修复测试数据"""
        fixed_data = fix_test_data(self._data)
        self.save(fixed_data)
        return fixed_data
    
    def update_all(self) -> Dict[str, Any]:
        """更新所有测试数据"""
        data = update_generator_test_data()
        self.save(data)
        return data
    
    @property
    def data(self) -> Dict[str, Any]:
        """获取当前测试数据"""
        return self._data
    
    @data.setter
    def data(self, value: Dict[str, Any]):
        """设置当前测试数据"""
        self._data = value
        self.save() 