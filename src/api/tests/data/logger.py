import logging
import os
from typing import Optional
from ..config import TEST_CONFIG

class TestDataLogger:
    """测试数据日志类"""
    
    def __init__(self, name: str = 'test_data'):
        """初始化日志记录器"""
        self.logger = logging.getLogger(name)
        self.logger.setLevel(TEST_CONFIG['LOG_LEVEL'])
        
        # 创建日志目录
        log_dir = os.path.dirname(TEST_CONFIG['LOG_FILE'])
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # 创建文件处理器
        file_handler = logging.FileHandler(TEST_CONFIG['LOG_FILE'])
        file_handler.setLevel(TEST_CONFIG['LOG_LEVEL'])
        
        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(TEST_CONFIG['LOG_LEVEL'])
        
        # 创建格式化器
        formatter = logging.Formatter(TEST_CONFIG['LOG_FORMAT'])
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # 添加处理器
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def debug(self, message: str, *args, **kwargs):
        """记录调试信息"""
        self.logger.debug(message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        """记录信息"""
        self.logger.info(message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """记录警告信息"""
        self.logger.warning(message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        """记录错误信息"""
        self.logger.error(message, *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        """记录严重错误信息"""
        self.logger.critical(message, *args, **kwargs)
    
    def exception(self, message: str, *args, **kwargs):
        """记录异常信息"""
        self.logger.exception(message, *args, **kwargs)
    
    def log_test_data(self, data: dict, operation: str):
        """记录测试数据操作"""
        self.info(f"{operation} test data: {data}")
    
    def log_error(self, error: Exception, operation: str):
        """记录错误"""
        self.error(f"{operation} failed: {str(error)}")
    
    def log_validation(self, data: dict, is_valid: bool):
        """记录验证结果"""
        if is_valid:
            self.info(f"Test data validation successful: {data}")
        else:
            self.warning(f"Test data validation failed: {data}")
    
    def log_generation(self, data: dict):
        """记录生成结果"""
        self.info(f"Test data generated: {data}")
    
    def log_loading(self, data: dict):
        """记录加载结果"""
        self.info(f"Test data loaded: {data}")
    
    def log_saving(self, data: dict):
        """记录保存结果"""
        self.info(f"Test data saved: {data}")
    
    def log_update(self, data: dict):
        """记录更新结果"""
        self.info(f"Test data updated: {data}")
    
    def log_delete(self, algorithm: str):
        """记录删除结果"""
        self.info(f"Test data deleted for algorithm: {algorithm}")
    
    def log_clear(self):
        """记录清空结果"""
        self.info("Test data cleared")

# 创建默认日志记录器
logger = TestDataLogger() 