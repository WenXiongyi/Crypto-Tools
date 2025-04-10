from flask import Blueprint, request, jsonify
from functools import wraps
import logging
from ..core.utils import setup_logger, create_response
from ..core.exceptions import CryptoError
from ..algorithms.symmetric import aes, sm4, rc6
from ..algorithms.hash import hash_algorithms
from ..algorithms.public_key import rsa, ecc
from ..algorithms.encoding import encoding

# 设置日志
logger = setup_logger('api')

# 创建蓝图
api = Blueprint('api', __name__)

def handle_errors(f):
    """错误处理装饰器"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except CryptoError as e:
            logger.error(f"Crypto error: {str(e)}")
            return jsonify(create_response(False, error=str(e), code=e.code))
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return jsonify(create_response(False, error="Internal server error", code=500))
    return wrapper

@api.route('/encrypt', methods=['POST'])
@handle_errors
def encrypt():
    """加密接口"""
    data = request.get_json()
    algorithm = data.get('algorithm')
    
    if algorithm == "AES":
        key = data.get('key')
        plaintext = data.get('plaintext')
        return jsonify({'ciphertext': aes.encrypt(key, plaintext)})
    elif algorithm == "SM4":
        key = data.get('key')
        plaintext = data.get('plaintext')
        return jsonify({'ciphertext': sm4.encrypt(key, plaintext)})
    elif algorithm == "RC6":
        key = data.get('key')
        plaintext = data.get('plaintext')
        return jsonify({'ciphertext': rc6.encrypt(key, plaintext)})
    elif algorithm == "RSA":
        public_key = data.get('publickey')
        plaintext = data.get('plaintext')
        return jsonify({'ciphertext': rsa.encrypt(public_key, plaintext)})
    elif algorithm == "ECC":
        public_key = data.get('publickey')
        plaintext = data.get('plaintext')
        return jsonify({'ciphertext': ecc.encrypt(public_key, plaintext)})
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400

@api.route('/decrypt', methods=['POST'])
@handle_errors
def decrypt():
    """解密接口"""
    data = request.get_json()
    algorithm = data.get('algorithm')
    
    if algorithm == "AES":
        key = data.get('key')
        ciphertext = data.get('ciphertext')
        return jsonify({'plaintext': aes.decrypt(key, ciphertext)})
    elif algorithm == "SM4":
        key = data.get('key')
        ciphertext = data.get('ciphertext')
        return jsonify({'plaintext': sm4.decrypt(key, ciphertext)})
    elif algorithm == "RC6":
        key = data.get('key')
        ciphertext = data.get('ciphertext')
        return jsonify({'plaintext': rc6.decrypt(key, ciphertext)})
    elif algorithm == "RSA":
        private_key = data.get('privatekey')
        ciphertext = data.get('ciphertext')
        return jsonify({'plaintext': rsa.decrypt(private_key, ciphertext)})
    elif algorithm == "ECC":
        private_key = data.get('privatekey')
        ciphertext = data.get('ciphertext')
        return jsonify({'plaintext': ecc.decrypt(private_key, ciphertext)})
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400

@api.route('/hash', methods=['POST'])
@handle_errors
def hash_data():
    """哈希计算接口"""
    data = request.get_json()
    algorithm = data.get('algorithm')
    plaintext = data.get('plaintext')
    
    if algorithm == "SHA1":
        return jsonify({'hash': hash_algorithms.sha1_hash(plaintext)})
    elif algorithm == "SHA256":
        return jsonify({'hash': hash_algorithms.sha256_hash(plaintext)})
    elif algorithm == "SHA3":
        return jsonify({'hash': hash_algorithms.sha3_hash(plaintext)})
    elif algorithm == "RIPEMD160":
        return jsonify({'hash': hash_algorithms.ripemd160_hash(plaintext)})
    elif algorithm == "HMACSHA1":
        key = data.get('key')
        return jsonify({'hash': hash_algorithms.hmac_sha1(key, plaintext)})
    elif algorithm == "HMACSHA256":
        key = data.get('key')
        return jsonify({'hash': hash_algorithms.hmac_sha256(key, plaintext)})
    elif algorithm == "PBKDF2":
        return jsonify({'hash': hash_algorithms.pbkdf2_hash(plaintext)})
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400

@api.route('/encode', methods=['POST'])
@handle_errors
def encode():
    """编码接口"""
    data = request.get_json()
    algorithm = data.get('algorithm')
    plaintext = data.get('plaintext')
    
    if algorithm == "Base64":
        return jsonify({'encoded': encoding.base64_encode(plaintext)})
    elif algorithm == "UTF-8":
        return jsonify({'encoded': encoding.utf8_encode(plaintext)})
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400

@api.route('/decode', methods=['POST'])
@handle_errors
def decode():
    """解码接口"""
    data = request.get_json()
    algorithm = data.get('algorithm')
    ciphertext = data.get('ciphertext')
    
    if algorithm == "Base64":
        return jsonify({'decoded': encoding.base64_decode(ciphertext)})
    elif algorithm == "UTF-8":
        return jsonify({'decoded': encoding.utf8_decode(ciphertext)})
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400

@api.route('/generate', methods=['POST'])
@handle_errors
def generate_keys():
    """密钥生成接口"""
    data = request.get_json()
    algorithm = data.get('algorithm')
    
    if algorithm == "RSA" or algorithm == "RSA-SHA1":
        return jsonify(rsa.generate_key())
    elif algorithm == "ECC":
        return jsonify(ecc.generate_key())
    elif algorithm == "ECDSA":
        return jsonify(ecc.generate_ecdsa_key())
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400

@api.route('/sign', methods=['POST'])
@handle_errors
def sign():
    """签名接口"""
    data = request.get_json()
    algorithm = data.get('algorithm')
    
    if algorithm == "RSA-SHA1":
        private_key = data.get('privatekey')
        plaintext = data.get('plaintext')
        return jsonify({'signature': rsa.sign(private_key, plaintext)})
    elif algorithm == "ECDSA":
        private_key = data.get('privatekey')
        plaintext = data.get('plaintext')
        return jsonify({'signature': ecc.ecdsa_sign(private_key, plaintext)})
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400

@api.route('/verify', methods=['POST'])
@handle_errors
def verify():
    """验证签名接口"""
    data = request.get_json()
    algorithm = data.get('algorithm')
    
    if algorithm == "RSA-SHA1":
        public_key = data.get('publickey')
        plaintext = data.get('plaintext')
        signature = data.get('signature')
        return jsonify({'result': rsa.verify(public_key, plaintext, signature)})
    elif algorithm == "ECDSA":
        public_key = data.get('publickey')
        plaintext = data.get('plaintext')
        signature = data.get('signature')
        return jsonify({'result': ecc.ecdsa_verify(public_key, plaintext, signature)})
    else:
        return jsonify({'error': 'Unsupported algorithm'}), 400 