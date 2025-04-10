from flask import Flask, request, jsonify, send_from_directory
from src.algorithms.symmetric.aes import encrypt as aes_encrypt, decrypt as aes_decrypt
from src.algorithms.symmetric.sm4 import encrypt as sm4_encrypt, decrypt as sm4_decrypt
from src.algorithms.symmetric.rc6 import encrypt as rc6_encrypt, decrypt as rc6_decrypt
from src.algorithms.hash.hash import (
    sha1_hash, sha256_hash, sha3_hash, ripemd160_hash,
    hmac_sha1, hmac_sha256, pbkdf2_derive
)
from src.algorithms.public_key.rsa import (
    encrypt as rsa_encrypt,
    decrypt as rsa_decrypt,
    sign as rsa_sign,
    verify as rsa_verify,
    generate_key as rsa_generate_key
)
from src.algorithms.public_key.ecc import (
    encrypt as ecc_encrypt,
    decrypt as ecc_decrypt,
    ecdsa_sign,
    ecdsa_verify,
    generate_key as ecc_generate_key
)
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA1, SHA256, SHA3_256, RIPEMD160, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import json
import os

app = Flask(__name__)

# 算法映射
SYMMETRIC_ALGORITHMS = {
    'AES': (aes_encrypt, aes_decrypt),
    'SM4': (sm4_encrypt, sm4_decrypt),
    'RC6': (rc6_encrypt, rc6_decrypt)
}

HASH_ALGORITHMS = {
    'SHA1': sha1_hash,
    'SHA256': sha256_hash,
    'SHA3': sha3_hash,
    'RIPEMD160': ripemd160_hash,
    'HMAC-SHA1': hmac_sha1,
    'HMAC-SHA256': hmac_sha256,
    'PBKDF2': pbkdf2_derive
}

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

def handle_symmetric_encryption(algorithm, key, plaintext, mode='encrypt'):
    try:
        if algorithm == 'AES':
            key = pad(key.encode(), AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC)
            if mode == 'encrypt':
                ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
                iv = b64encode(cipher.iv).decode('utf-8')
                ct = b64encode(ct_bytes).decode('utf-8')
                return json.dumps({'iv': iv, 'ciphertext': ct})
            else:
                try:
                    iv = b64decode(json.loads(plaintext)['iv'])
                    ct = b64decode(json.loads(plaintext)['ciphertext'])
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    return pt.decode('utf-8')
                except (ValueError, KeyError) as e:
                    return str(e)
        elif algorithm == 'SM4':
            if mode == 'encrypt':
                return sm4_encrypt(key, plaintext)
            else:
                return sm4_decrypt(key, plaintext)
        elif algorithm == 'RC6':
            if mode == 'encrypt':
                return rc6_encrypt(key, plaintext)
            else:
                return rc6_decrypt(key, plaintext)
        return "暂不支持该算法"
    except Exception as e:
        return str(e)

def handle_hash(algorithm, plaintext, key=None):
    try:
        if algorithm == 'SHA1':
            return SHA1.new(plaintext.encode()).hexdigest()
        elif algorithm == 'SHA256':
            return SHA256.new(plaintext.encode()).hexdigest()
        elif algorithm == 'SHA3':
            return SHA3_256.new(plaintext.encode()).hexdigest()
        elif algorithm == 'RIPEMD160':
            return RIPEMD160.new(plaintext.encode()).hexdigest()
        elif algorithm == 'HMAC-SHA1':
            h = HMAC.new(key.encode(), digestmod=SHA1)
            h.update(plaintext.encode())
            return h.hexdigest()
        elif algorithm == 'HMAC-SHA256':
            h = HMAC.new(key.encode(), digestmod=SHA256)
            h.update(plaintext.encode())
            return h.hexdigest()
        elif algorithm == 'PBKDF2':
            salt = b'salt'  # 在实际应用中应该使用随机salt
            return b64encode(PBKDF2(plaintext.encode(), salt, 32)).decode()
        return "暂不支持该算法"
    except Exception as e:
        return str(e)

def handle_encoding(algorithm, text, mode='encode'):
    try:
        if algorithm == 'Base64':
            if mode == 'encode':
                return b64encode(text.encode()).decode()
            else:
                return b64decode(text).decode()
        elif algorithm == 'UTF-8':
            if mode == 'encode':
                return text.encode('utf-8').hex()
            else:
                return bytes.fromhex(text).decode('utf-8')
        return "暂不支持该算法"
    except Exception as e:
        print(f"编码/解码错误: {str(e)}")
        return str(e)

def handle_asymmetric_encryption(algorithm, key, plaintext, mode='encrypt'):
    try:
        if algorithm == 'RSA':
            if mode == 'encrypt':
                public_key = RSA.import_key(key)
                cipher = PKCS1_OAEP.new(public_key)
                ciphertext = cipher.encrypt(plaintext.encode())
                return b64encode(ciphertext).decode('utf-8')
            else:
                private_key = RSA.import_key(key)
                cipher = PKCS1_OAEP.new(private_key)
                plaintext = cipher.decrypt(b64decode(plaintext))
                return plaintext.decode('utf-8')
        return "暂不支持该算法"
    except Exception as e:
        return str(e)

def handle_signature(algorithm, private_key, message):
    try:
        if algorithm in ['ECC', 'ECDSA']:
            key = ECC.import_key(private_key)
            h = SHA256.new(message.encode())
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            return b64encode(signature).decode('utf-8')
        elif algorithm == 'RSA-SHA1':
            key = RSA.import_key(private_key)
            h = SHA1.new(message.encode())
            signer = pkcs1_15.new(key)
            signature = signer.sign(h)
            return b64encode(signature).decode('utf-8')
        return "暂不支持该算法"
    except Exception as e:
        return str(e)

def handle_verification(algorithm, public_key, message, signature):
    try:
        if algorithm in ['ECC', 'ECDSA']:
            key = ECC.import_key(public_key)
            h = SHA256.new(message.encode())
            verifier = DSS.new(key, 'fips-186-3')
            try:
                verifier.verify(h, b64decode(signature))
                return True
            except ValueError:
                return False
        elif algorithm == 'RSA-SHA1':
            key = RSA.import_key(public_key)
            h = SHA1.new(message.encode())
            verifier = pkcs1_15.new(key)
            try:
                verifier.verify(h, b64decode(signature))
                return True
            except (ValueError, TypeError):
                return False
        return False
    except Exception as e:
        print(f"验证签名时出错: {str(e)}")
        return False

@app.route('/generate', methods=['POST'])
def generate():
    try:
        data = request.get_json()
        algorithm = data.get('algorithm')
        
        if algorithm == 'RSA':
            key = RSA.generate(1024)  # RSA-1024bit
            private_key = key.export_key().decode('utf-8')
            public_key = key.publickey().export_key().decode('utf-8')
        elif algorithm == 'RSA-SHA1':
            key = RSA.generate(2048)  # RSA-SHA1使用2048位密钥
            private_key = key.export_key().decode('utf-8')
            public_key = key.publickey().export_key().decode('utf-8')
        elif algorithm in ['ECC', 'ECDSA']:
            key = ECC.generate(curve='P-256')  # ECC-256bit，使用标准NIST P-256曲线
            private_key = key.export_key(format='PEM')  # 已经是字符串，不需要decode
            public_key = key.public_key().export_key(format='PEM')  # 已经是字符串，不需要decode
        else:
            return jsonify({'error': '不支持的算法'})
        
        return jsonify({
            'private_key': private_key,
            'public_key': public_key
        })
    except Exception as e:
        print(f"生成密钥对时出错: {str(e)}")
        return jsonify({'error': f'生成密钥对失败: {str(e)}'})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        algorithm = data.get('algorithm')
        key = data.get('key', '')
        plaintext = data.get('plaintext')

        if not plaintext:
            return jsonify({'error': '请提供原文'})

        if algorithm in ['AES', 'SM4', 'RC6']:
            if not key:
                return jsonify({'error': '请提供密钥'})
            result = handle_symmetric_encryption(algorithm, key, plaintext, 'encrypt')
        elif algorithm in ['SHA1', 'SHA256', 'SHA3', 'RIPEMD160', 'HMAC-SHA1', 'HMAC-SHA256', 'PBKDF2']:
            result = handle_hash(algorithm, plaintext, key)
        elif algorithm in ['Base64', 'UTF-8']:
            result = handle_encoding(algorithm, plaintext, 'encode')
        elif algorithm == 'RSA':
            if not key:
                return jsonify({'error': '请提供公钥'})
            result = handle_asymmetric_encryption('RSA', key, plaintext, 'encrypt')
        else:
            return jsonify({'error': '不支持的算法'})

        return jsonify({'ciphertext': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        algorithm = data.get('algorithm')
        ciphertext = data.get('ciphertext')

        if not algorithm or not ciphertext:
            return jsonify({'error': '缺少必要参数'})

        if algorithm in ['Base64', 'UTF-8']:
            result = handle_encoding(algorithm, ciphertext, 'decode')
        else:
            key = data.get('key')
            if not key:
                return jsonify({'error': '缺少必要参数'})
                
            if algorithm in ['AES', 'SM4', 'RC6']:
                result = handle_symmetric_encryption(algorithm, key, ciphertext, 'decrypt')
            elif algorithm == 'RSA':
                result = handle_asymmetric_encryption('RSA', key, ciphertext, 'decrypt')
            else:
                return jsonify({'error': '不支持的算法'})

        return jsonify({'plaintext': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/sign', methods=['POST'])
def sign():
    try:
        data = request.get_json()
        algorithm = data.get('algorithm')
        private_key = data.get('private_key')
        message = data.get('plaintext')

        if not all([algorithm, private_key, message]):
            return jsonify({'error': '缺少必要参数'})

        signature = handle_signature(algorithm, private_key, message)
        if isinstance(signature, str) and signature.startswith('Error'):
            return jsonify({'error': signature})
        
        return jsonify({'signature': signature})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/verify', methods=['POST'])
def verify():
    try:
        data = request.get_json()
        algorithm = data.get('algorithm')
        public_key = data.get('public_key')
        message = data.get('plaintext')  # 从前端接收plaintext参数
        signature = data.get('signature')

        if not all([algorithm, public_key, message, signature]):
            missing_params = []
            if not algorithm: missing_params.append('algorithm')
            if not public_key: missing_params.append('public_key')
            if not message: missing_params.append('message')
            if not signature: missing_params.append('signature')
            return jsonify({'error': f'缺少必要参数: {", ".join(missing_params)}'}), 400

        is_valid = handle_verification(algorithm, public_key, message, signature)
        return jsonify({'verified': is_valid})
    except Exception as e:
        print(f"验证签名时出错: {str(e)}")  # 添加错误日志
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 