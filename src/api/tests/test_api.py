import unittest
import json
from flask import Flask
from ..factory import create_app
from ..config import TestingConfig

class TestAPI(unittest.TestCase):
    """API测试类"""
    
    def setUp(self):
        """测试前设置"""
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
    
    def tearDown(self):
        """测试后清理"""
        self.app_context.pop()
    
    def test_encrypt(self):
        """测试加密接口"""
        data = {
            "algorithm": "aes",
            "key": "test_key",
            "plaintext": "test_plaintext"
        }
        response = self.client.post(
            '/api/v1/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.data)
        self.assertTrue(result['success'])
        self.assertIn('ciphertext', result['data'])
    
    def test_decrypt(self):
        """测试解密接口"""
        data = {
            "algorithm": "aes",
            "key": "test_key",
            "ciphertext": "test_ciphertext"
        }
        response = self.client.post(
            '/api/v1/decrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.data)
        self.assertTrue(result['success'])
        self.assertIn('plaintext', result['data'])
    
    def test_hash(self):
        """测试哈希接口"""
        data = {
            "algorithm": "sha256",
            "plaintext": "test_plaintext"
        }
        response = self.client.post(
            '/api/v1/hash',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.data)
        self.assertTrue(result['success'])
        self.assertIn('hash', result['data'])
    
    def test_generate(self):
        """测试密钥生成接口"""
        data = {
            "algorithm": "rsa",
            "key_size": 2048
        }
        response = self.client.post(
            '/api/v1/generate',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.data)
        self.assertTrue(result['success'])
        self.assertIn('public_key', result['data'])
        self.assertIn('private_key', result['data'])
    
    def test_sign(self):
        """测试签名接口"""
        data = {
            "algorithm": "rsa",
            "private_key": "test_private_key",
            "plaintext": "test_plaintext"
        }
        response = self.client.post(
            '/api/v1/sign',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.data)
        self.assertTrue(result['success'])
        self.assertIn('signature', result['data'])
    
    def test_verify(self):
        """测试验证签名接口"""
        data = {
            "algorithm": "rsa",
            "public_key": "test_public_key",
            "plaintext": "test_plaintext",
            "signature": "test_signature"
        }
        response = self.client.post(
            '/api/v1/verify',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.data)
        self.assertTrue(result['success'])
        self.assertIn('result', result['data'])
    
    def test_invalid_algorithm(self):
        """测试无效算法"""
        data = {
            "algorithm": "invalid",
            "key": "test_key",
            "plaintext": "test_plaintext"
        }
        response = self.client.post(
            '/api/v1/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        result = json.loads(response.data)
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    def test_missing_parameters(self):
        """测试缺少参数"""
        data = {
            "algorithm": "aes"
        }
        response = self.client.post(
            '/api/v1/encrypt',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        result = json.loads(response.data)
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    def test_invalid_content_type(self):
        """测试无效的内容类型"""
        data = {
            "algorithm": "aes",
            "key": "test_key",
            "plaintext": "test_plaintext"
        }
        response = self.client.post(
            '/api/v1/encrypt',
            data=json.dumps(data),
            content_type='text/plain'
        )
        self.assertEqual(response.status_code, 415)
        result = json.loads(response.data)
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    def test_health_check(self):
        """测试健康检查接口"""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.data)
        self.assertEqual(result['status'], 'healthy')
        self.assertIn('version', result)

if __name__ == '__main__':
    unittest.main() 