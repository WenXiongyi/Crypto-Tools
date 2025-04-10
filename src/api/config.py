import os
from typing import Dict, Any

class Config:
    """基础配置类"""
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev')
    
    # 数据库配置
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///crypto.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 日志配置
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = 'crypto_api.log'
    
    # API配置
    API_PREFIX = '/api/v1'
    API_TITLE = 'Crypto API'
    API_VERSION = '1.0.0'
    API_DESCRIPTION = 'Cryptographic Algorithm API'
    
    # 安全配置
    CORS_ORIGINS = ['*']
    RATE_LIMIT = '100/minute'
    
    # 算法配置
    ALGORITHMS: Dict[str, Any] = {
        'symmetric': {
            'aes': {
                'key_sizes': [128, 192, 256],
                'modes': ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
            },
            'sm4': {
                'key_sizes': [128],
                'modes': ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
            },
            'rc6': {
                'key_sizes': [128, 192, 256],
                'rounds': 20
            }
        },
        'asymmetric': {
            'rsa': {
                'key_sizes': [1024, 2048, 3072, 4096],
                'padding': ['PKCS1', 'OAEP']
            },
            'ecc': {
                'curves': ['P-256', 'P-384', 'P-521'],
                'signature_algorithms': ['ECDSA']
            }
        },
        'hash': {
            'sha1': {
                'output_size': 160
            },
            'sha256': {
                'output_size': 256
            },
            'sha3': {
                'output_size': 256
            },
            'ripemd160': {
                'output_size': 160
            }
        }
    }

class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    """生产环境配置"""
    SECRET_KEY = os.environ.get('SECRET_KEY')
    LOG_LEVEL = 'WARNING'
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '').split(',')

# 配置映射
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config(config_name: str = None) -> Config:
    """获取配置"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')
    return config[config_name] 