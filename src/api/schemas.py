from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class BaseRequest(BaseModel):
    """基础请求模型"""
    algorithm: str = Field(..., description="算法名称")

class EncryptRequest(BaseRequest):
    """加密请求模型"""
    key: str = Field(..., description="密钥")
    plaintext: str = Field(..., description="明文")

class DecryptRequest(BaseRequest):
    """解密请求模型"""
    key: str = Field(..., description="密钥")
    ciphertext: str = Field(..., description="密文")

class HashRequest(BaseRequest):
    """哈希计算请求模型"""
    plaintext: str = Field(..., description="输入文本")

class GenerateKeyRequest(BaseRequest):
    """密钥生成请求模型"""
    key_size: Optional[int] = Field(2048, description="密钥长度")

class SignRequest(BaseRequest):
    """签名请求模型"""
    private_key: str = Field(..., description="私钥")
    plaintext: str = Field(..., description="明文")

class VerifyRequest(BaseRequest):
    """验证签名请求模型"""
    public_key: str = Field(..., description="公钥")
    plaintext: str = Field(..., description="明文")
    signature: str = Field(..., description="签名")

class BaseResponse(BaseModel):
    """基础响应模型"""
    success: bool = Field(..., description="操作是否成功")
    code: int = Field(..., description="状态码")
    error: Optional[str] = Field(None, description="错误信息")
    data: Optional[Dict[str, Any]] = Field(None, description="响应数据")

class EncryptResponse(BaseResponse):
    """加密响应模型"""
    data: Dict[str, str] = Field(..., description="加密结果")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "code": 200,
                "data": {
                    "ciphertext": "base64_encoded_ciphertext"
                }
            }
        }

class DecryptResponse(BaseResponse):
    """解密响应模型"""
    data: Dict[str, str] = Field(..., description="解密结果")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "code": 200,
                "data": {
                    "plaintext": "decrypted_text"
                }
            }
        }

class HashResponse(BaseResponse):
    """哈希计算响应模型"""
    data: Dict[str, str] = Field(..., description="哈希结果")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "code": 200,
                "data": {
                    "hash": "hash_value"
                }
            }
        }

class GenerateKeyResponse(BaseResponse):
    """密钥生成响应模型"""
    data: Dict[str, str] = Field(..., description="生成的密钥对")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "code": 200,
                "data": {
                    "public_key": "base64_encoded_public_key",
                    "private_key": "base64_encoded_private_key"
                }
            }
        }

class SignResponse(BaseResponse):
    """签名响应模型"""
    data: Dict[str, str] = Field(..., description="签名结果")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "code": 200,
                "data": {
                    "signature": "base64_encoded_signature"
                }
            }
        }

class VerifyResponse(BaseResponse):
    """验证签名响应模型"""
    data: Dict[str, bool] = Field(..., description="验证结果")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "code": 200,
                "data": {
                    "result": True
                }
            }
        } 