class CryptoError(Exception):
    """密码算法基础异常类"""
    def __init__(self, message: str, code: int = 500):
        self.message = message
        self.code = code
        super().__init__(self.message)

class InvalidKeyError(CryptoError):
    """无效密钥异常"""
    def __init__(self, message: str = "Invalid key"):
        super().__init__(message, 400)

class InvalidDataError(CryptoError):
    """无效数据异常"""
    def __init__(self, message: str = "Invalid data"):
        super().__init__(message, 400)

class AlgorithmError(CryptoError):
    """算法执行异常"""
    def __init__(self, message: str = "Algorithm execution failed"):
        super().__init__(message, 500)

class ParameterError(CryptoError):
    """参数错误异常"""
    def __init__(self, message: str = "Invalid parameters"):
        super().__init__(message, 400)

class KeyGenerationError(CryptoError):
    """密钥生成异常"""
    def __init__(self, message: str = "Key generation failed"):
        super().__init__(message, 500)

class SignatureError(CryptoError):
    """签名异常"""
    def __init__(self, message: str = "Signature operation failed"):
        super().__init__(message, 500)

class VerificationError(CryptoError):
    """验证异常"""
    def __init__(self, message: str = "Verification failed"):
        super().__init__(message, 400) 