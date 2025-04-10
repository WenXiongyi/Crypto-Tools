import os
import tempfile

# 测试配置
TEST_CONFIG = {
    'TESTING': True,
    'DEBUG': True,
    'SECRET_KEY': 'test_secret_key',
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'LOG_LEVEL': 'DEBUG',
    'LOG_FILE': os.path.join(tempfile.gettempdir(), 'crypto_api_test.log'),
    'API_PREFIX': '/api/v1',
    'API_TITLE': 'Crypto API Test',
    'API_VERSION': '1.0.0',
    'API_DESCRIPTION': 'Cryptographic Algorithm API Test',
    'CORS_ORIGINS': ['*'],
    'RATE_LIMIT': '100/minute'
}

# 测试数据
TEST_DATA = {
    'aes': {
        'key': 'test_key_16bytes',
        'plaintext': 'test_plaintext',
        'ciphertext': 'test_ciphertext'
    },
    'rsa': {
        'public_key': 'test_public_key',
        'private_key': 'test_private_key',
        'plaintext': 'test_plaintext',
        'signature': 'test_signature'
    },
    'sha256': {
        'plaintext': 'test_plaintext',
        'hash': 'test_hash'
    }
}

# 测试算法配置
TEST_ALGORITHMS = {
    'symmetric': {
        'aes': {
            'key_sizes': [128],
            'modes': ['ECB']
        }
    },
    'asymmetric': {
        'rsa': {
            'key_sizes': [1024],
            'padding': ['PKCS1']
        }
    },
    'hash': {
        'sha256': {
            'output_size': 256
        }
    }
} 