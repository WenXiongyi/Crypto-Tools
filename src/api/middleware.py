from flask import request, g
import time
import logging
from functools import wraps
from ..core.utils import setup_logger

logger = setup_logger('middleware')

def log_request(f):
    """请求日志中间件"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g.start_time = time.time()
        
        # 记录请求信息
        logger.info(f"Request: {request.method} {request.path}")
        logger.info(f"Headers: {dict(request.headers)}")
        logger.info(f"Body: {request.get_json()}")
        
        # 执行视图函数
        response = f(*args, **kwargs)
        
        # 记录响应信息
        duration = time.time() - g.start_time
        logger.info(f"Response: {response.status_code}")
        logger.info(f"Duration: {duration:.2f}s")
        
        return response
    return decorated_function

def validate_content_type(f):
    """内容类型验证中间件"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT']:
            if not request.is_json:
                return {
                    "success": False,
                    "error": "Content-Type must be application/json",
                    "code": 415
                }, 415
        return f(*args, **kwargs)
    return decorated_function

def handle_cors(f):
    """CORS处理中间件"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response
    return decorated_function

def rate_limit(f):
    """速率限制中间件"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # TODO: 实现速率限制逻辑
        return f(*args, **kwargs)
    return decorated_function

def error_handler(f):
    """错误处理中间件"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}")
            return {
                "success": False,
                "error": "Internal server error",
                "code": 500
            }, 500
    return decorated_function 