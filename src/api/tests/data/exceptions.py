class TestDataError(Exception):
    """测试数据基础异常类"""
    pass

class InvalidAlgorithmError(TestDataError):
    """无效算法异常"""
    def __init__(self, algorithm: str):
        super().__init__(f"Invalid algorithm: {algorithm}")

class InvalidKeySizeError(TestDataError):
    """无效密钥长度异常"""
    def __init__(self, algorithm: str, key_size: int):
        super().__init__(f"Invalid key size {key_size} for algorithm {algorithm}")

class InvalidModeError(TestDataError):
    """无效加密模式异常"""
    def __init__(self, algorithm: str, mode: str):
        super().__init__(f"Invalid mode {mode} for algorithm {algorithm}")

class InvalidPaddingError(TestDataError):
    """无效填充方式异常"""
    def __init__(self, algorithm: str, padding: str):
        super().__init__(f"Invalid padding {padding} for algorithm {algorithm}")

class InvalidCurveError(TestDataError):
    """无效曲线异常"""
    def __init__(self, curve: str):
        super().__init__(f"Invalid curve: {curve}")

class MissingParameterError(TestDataError):
    """缺少参数异常"""
    def __init__(self, parameter: str):
        super().__init__(f"Missing required parameter: {parameter}")

class InvalidDataError(TestDataError):
    """无效数据异常"""
    def __init__(self, message: str = "Invalid data format"):
        super().__init__(message)

class EncryptionError(TestDataError):
    """加密异常"""
    def __init__(self, message: str = "Encryption failed"):
        super().__init__(message)

class DecryptionError(TestDataError):
    """解密异常"""
    def __init__(self, message: str = "Decryption failed"):
        super().__init__(message)

class SignatureError(TestDataError):
    """签名异常"""
    def __init__(self, message: str = "Signature failed"):
        super().__init__(message)

class VerificationError(TestDataError):
    """验证异常"""
    def __init__(self, message: str = "Verification failed"):
        super().__init__(message)

class HashError(TestDataError):
    """哈希计算异常"""
    def __init__(self, message: str = "Hash calculation failed"):
        super().__init__(message)

class TestDataValidationError(TestDataError):
    """测试数据验证异常"""
    def __init__(self, message: str = "Test data validation failed"):
        super().__init__(message)

class TestDataGenerationError(TestDataError):
    """测试数据生成异常"""
    def __init__(self, message: str = "Test data generation failed"):
        super().__init__(message)

class TestDataLoadingError(TestDataError):
    """测试数据加载异常"""
    def __init__(self, message: str = "Test data loading failed"):
        super().__init__(message)

class TestDataSavingError(TestDataError):
    """测试数据保存异常"""
    def __init__(self, message: str = "Test data saving failed"):
        super().__init__(message) 