from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .config import get_config
from .routes import api
from .middleware import log_request, validate_content_type, handle_cors, rate_limit, error_handler

db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address)

def create_app(config_name=None):
    """创建Flask应用"""
    app = Flask(__name__)
    
    # 加载配置
    config = get_config(config_name)
    app.config.from_object(config)
    
    # 初始化扩展
    db.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": config.CORS_ORIGINS}})
    limiter.init_app(app)
    
    # 注册蓝图
    app.register_blueprint(api, url_prefix=config.API_PREFIX)
    
    # 注册中间件
    app.before_request(log_request)
    app.before_request(validate_content_type)
    app.after_request(handle_cors)
    app.before_request(rate_limit)
    app.after_request(error_handler)
    
    # 创建数据库表
    with app.app_context():
        db.create_all()
    
    return app

def init_app(app):
    """初始化应用"""
    # 注册错误处理器
    @app.errorhandler(404)
    def not_found(error):
        return {
            "success": False,
            "error": "Not found",
            "code": 404
        }, 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return {
            "success": False,
            "error": "Method not allowed",
            "code": 405
        }, 405
    
    @app.errorhandler(500)
    def internal_error(error):
        return {
            "success": False,
            "error": "Internal server error",
            "code": 500
        }, 500
    
    # 注册健康检查路由
    @app.route('/health')
    def health_check():
        return {
            "status": "healthy",
            "version": app.config['API_VERSION']
        } 