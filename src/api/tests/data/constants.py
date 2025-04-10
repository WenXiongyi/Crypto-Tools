# 算法常量
ALGORITHMS = {
    'symmetric': ['aes', 'sm4', 'rc6'],
    'asymmetric': ['rsa', 'ecc'],
    'hash': ['sha1', 'sha256', 'sha3', 'ripemd160']
}

# 密钥长度常量
KEY_SIZES = {
    'aes': [128, 192, 256],
    'sm4': [128],
    'rc6': [128, 192, 256],
    'rsa': [1024, 2048, 3072, 4096],
    'ecc': ['P-256', 'P-384', 'P-521']
}

# 加密模式常量
MODES = {
    'aes': ['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
    'sm4': ['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
    'rc6': ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
}

# 填充方式常量
PADDING = {
    'rsa': ['PKCS1', 'OAEP'],
    'ecc': ['ECDSA']
}

# 哈希输出长度常量
HASH_SIZES = {
    'sha1': 160,
    'sha256': 256,
    'sha3': 256,
    'ripemd160': 160
}

# 测试数据默认值
DEFAULT_VALUES = {
    'key_size': 2048,
    'mode': 'CBC',
    'padding': 'PKCS1',
    'curve': 'P-256',
    'algorithm': 'sha256'
}

# 错误消息常量
ERROR_MESSAGES = {
    'invalid_algorithm': 'Invalid algorithm',
    'invalid_key_size': 'Invalid key size',
    'invalid_mode': 'Invalid mode',
    'invalid_padding': 'Invalid padding',
    'invalid_curve': 'Invalid curve',
    'missing_parameters': 'Missing required parameters',
    'invalid_data': 'Invalid data format',
    'encryption_failed': 'Encryption failed',
    'decryption_failed': 'Decryption failed',
    'signature_failed': 'Signature failed',
    'verification_failed': 'Verification failed',
    'hash_failed': 'Hash calculation failed'
}

# 状态码常量
STATUS_CODES = {
    'success': 200,
    'bad_request': 400,
    'unauthorized': 401,
    'forbidden': 403,
    'not_found': 404,
    'method_not_allowed': 405,
    'internal_error': 500
}

# 响应消息常量
RESPONSE_MESSAGES = {
    'success': 'Operation successful',
    'error': 'Operation failed',
    'invalid_request': 'Invalid request',
    'server_error': 'Internal server error'
} 