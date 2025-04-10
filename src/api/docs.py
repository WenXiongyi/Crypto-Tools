from flask_swagger_ui import get_swaggerui_blueprint

def init_swagger(app):
    """初始化Swagger UI"""
    SWAGGER_URL = '/api/docs'
    API_URL = '/static/swagger.json'
    
    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'app_name': app.config['API_TITLE']
        }
    )
    
    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

def generate_swagger_json(app):
    """生成Swagger JSON文档"""
    swagger = {
        "swagger": "2.0",
        "info": {
            "title": app.config['API_TITLE'],
            "version": app.config['API_VERSION'],
            "description": app.config['API_DESCRIPTION']
        },
        "basePath": app.config['API_PREFIX'],
        "schemes": ["http", "https"],
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "paths": {
            "/encrypt": {
                "post": {
                    "summary": "加密数据",
                    "description": "使用指定的算法加密数据",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/EncryptRequest"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "加密成功",
                            "schema": {
                                "$ref": "#/definitions/EncryptResponse"
                            }
                        }
                    }
                }
            },
            "/decrypt": {
                "post": {
                    "summary": "解密数据",
                    "description": "使用指定的算法解密数据",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/DecryptRequest"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "解密成功",
                            "schema": {
                                "$ref": "#/definitions/DecryptResponse"
                            }
                        }
                    }
                }
            },
            "/hash": {
                "post": {
                    "summary": "计算哈希",
                    "description": "使用指定的算法计算数据的哈希值",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/HashRequest"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "哈希计算成功",
                            "schema": {
                                "$ref": "#/definitions/HashResponse"
                            }
                        }
                    }
                }
            },
            "/generate": {
                "post": {
                    "summary": "生成密钥",
                    "description": "生成指定算法的密钥对",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/GenerateKeyRequest"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "密钥生成成功",
                            "schema": {
                                "$ref": "#/definitions/GenerateKeyResponse"
                            }
                        }
                    }
                }
            },
            "/sign": {
                "post": {
                    "summary": "签名数据",
                    "description": "使用指定的算法对数据进行签名",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/SignRequest"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "签名成功",
                            "schema": {
                                "$ref": "#/definitions/SignResponse"
                            }
                        }
                    }
                }
            },
            "/verify": {
                "post": {
                    "summary": "验证签名",
                    "description": "验证数据的签名",
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/VerifyRequest"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "验证成功",
                            "schema": {
                                "$ref": "#/definitions/VerifyResponse"
                            }
                        }
                    }
                }
            }
        },
        "definitions": {
            "BaseRequest": {
                "type": "object",
                "required": ["algorithm"],
                "properties": {
                    "algorithm": {
                        "type": "string",
                        "description": "算法名称"
                    }
                }
            },
            "EncryptRequest": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseRequest"
                    },
                    {
                        "type": "object",
                        "required": ["key", "plaintext"],
                        "properties": {
                            "key": {
                                "type": "string",
                                "description": "密钥"
                            },
                            "plaintext": {
                                "type": "string",
                                "description": "明文"
                            }
                        }
                    }
                ]
            },
            "DecryptRequest": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseRequest"
                    },
                    {
                        "type": "object",
                        "required": ["key", "ciphertext"],
                        "properties": {
                            "key": {
                                "type": "string",
                                "description": "密钥"
                            },
                            "ciphertext": {
                                "type": "string",
                                "description": "密文"
                            }
                        }
                    }
                ]
            },
            "HashRequest": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseRequest"
                    },
                    {
                        "type": "object",
                        "required": ["plaintext"],
                        "properties": {
                            "plaintext": {
                                "type": "string",
                                "description": "输入文本"
                            }
                        }
                    }
                ]
            },
            "GenerateKeyRequest": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseRequest"
                    },
                    {
                        "type": "object",
                        "properties": {
                            "key_size": {
                                "type": "integer",
                                "description": "密钥长度",
                                "default": 2048
                            }
                        }
                    }
                ]
            },
            "SignRequest": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseRequest"
                    },
                    {
                        "type": "object",
                        "required": ["private_key", "plaintext"],
                        "properties": {
                            "private_key": {
                                "type": "string",
                                "description": "私钥"
                            },
                            "plaintext": {
                                "type": "string",
                                "description": "明文"
                            }
                        }
                    }
                ]
            },
            "VerifyRequest": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseRequest"
                    },
                    {
                        "type": "object",
                        "required": ["public_key", "plaintext", "signature"],
                        "properties": {
                            "public_key": {
                                "type": "string",
                                "description": "公钥"
                            },
                            "plaintext": {
                                "type": "string",
                                "description": "明文"
                            },
                            "signature": {
                                "type": "string",
                                "description": "签名"
                            }
                        }
                    }
                ]
            },
            "BaseResponse": {
                "type": "object",
                "required": ["success", "code"],
                "properties": {
                    "success": {
                        "type": "boolean",
                        "description": "操作是否成功"
                    },
                    "code": {
                        "type": "integer",
                        "description": "状态码"
                    },
                    "error": {
                        "type": "string",
                        "description": "错误信息"
                    },
                    "data": {
                        "type": "object",
                        "description": "响应数据"
                    }
                }
            },
            "EncryptResponse": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseResponse"
                    },
                    {
                        "type": "object",
                        "required": ["data"],
                        "properties": {
                            "data": {
                                "type": "object",
                                "required": ["ciphertext"],
                                "properties": {
                                    "ciphertext": {
                                        "type": "string",
                                        "description": "加密结果"
                                    }
                                }
                            }
                        }
                    }
                ]
            },
            "DecryptResponse": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseResponse"
                    },
                    {
                        "type": "object",
                        "required": ["data"],
                        "properties": {
                            "data": {
                                "type": "object",
                                "required": ["plaintext"],
                                "properties": {
                                    "plaintext": {
                                        "type": "string",
                                        "description": "解密结果"
                                    }
                                }
                            }
                        }
                    }
                ]
            },
            "HashResponse": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseResponse"
                    },
                    {
                        "type": "object",
                        "required": ["data"],
                        "properties": {
                            "data": {
                                "type": "object",
                                "required": ["hash"],
                                "properties": {
                                    "hash": {
                                        "type": "string",
                                        "description": "哈希结果"
                                    }
                                }
                            }
                        }
                    }
                ]
            },
            "GenerateKeyResponse": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseResponse"
                    },
                    {
                        "type": "object",
                        "required": ["data"],
                        "properties": {
                            "data": {
                                "type": "object",
                                "required": ["public_key", "private_key"],
                                "properties": {
                                    "public_key": {
                                        "type": "string",
                                        "description": "公钥"
                                    },
                                    "private_key": {
                                        "type": "string",
                                        "description": "私钥"
                                    }
                                }
                            }
                        }
                    }
                ]
            },
            "SignResponse": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseResponse"
                    },
                    {
                        "type": "object",
                        "required": ["data"],
                        "properties": {
                            "data": {
                                "type": "object",
                                "required": ["signature"],
                                "properties": {
                                    "signature": {
                                        "type": "string",
                                        "description": "签名结果"
                                    }
                                }
                            }
                        }
                    }
                ]
            },
            "VerifyResponse": {
                "allOf": [
                    {
                        "$ref": "#/definitions/BaseResponse"
                    },
                    {
                        "type": "object",
                        "required": ["data"],
                        "properties": {
                            "data": {
                                "type": "object",
                                "required": ["result"],
                                "properties": {
                                    "result": {
                                        "type": "boolean",
                                        "description": "验证结果"
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        }
    }
    
    return swagger 