import unittest
from src.algorithms.public_key.rsa import (
    generate_key,
    encrypt,
    decrypt,
    sign,
    verify
)

class TestRSA(unittest.TestCase):
    def setUp(self):
        self.keys = generate_key()
        self.private_key = self.keys['privatekey']
        self.public_key = self.keys['publickey']
        self.plaintext = "这是一段测试文本"
        
    def test_encrypt_decrypt(self):
        """测试加密解密"""
        # 加密
        ciphertext = encrypt(self.public_key, self.plaintext)
        self.assertIsInstance(ciphertext, str)
        
        # 解密
        decrypted = decrypt(self.private_key, ciphertext)
        self.assertEqual(decrypted, self.plaintext)
        
    def test_sign_verify_sha1(self):
        """测试SHA1签名验证"""
        # 签名
        signature = sign(self.private_key, self.plaintext, 'sha1')
        self.assertIsInstance(signature, str)
        
        # 验证
        result = verify(self.public_key, self.plaintext, signature, 'sha1')
        self.assertEqual(result, 'valid')
        
    def test_sign_verify_sha256(self):
        """测试SHA256签名验证"""
        # 签名
        signature = sign(self.private_key, self.plaintext, 'sha256')
        self.assertIsInstance(signature, str)
        
        # 验证
        result = verify(self.public_key, self.plaintext, signature, 'sha256')
        self.assertEqual(result, 'valid')
        
    def test_invalid_signature(self):
        """测试无效签名"""
        # 生成签名
        signature = sign(self.private_key, self.plaintext)
        
        # 修改签名
        invalid_signature = signature[:-1] + '0'
        
        # 验证
        result = verify(self.public_key, self.plaintext, invalid_signature)
        self.assertEqual(result, 'invalid')
        
    def test_invalid_hash_algorithm(self):
        """测试无效的哈希算法"""
        with self.assertRaises(ValueError):
            sign(self.private_key, self.plaintext, 'md5')
        with self.assertRaises(ValueError):
            verify(self.public_key, self.plaintext, 'signature', 'md5')
            
    def test_empty_input(self):
        """测试空输入"""
        with self.assertRaises(ValueError):
            encrypt(self.public_key, "")
        with self.assertRaises(ValueError):
            decrypt(self.private_key, "")
        with self.assertRaises(ValueError):
            sign(self.private_key, "")
        with self.assertRaises(ValueError):
            verify(self.public_key, "", "signature")
            
    def test_invalid_key(self):
        """测试无效密钥"""
        with self.assertRaises(ValueError):
            encrypt("invalid_key", self.plaintext)
        with self.assertRaises(ValueError):
            decrypt("invalid_key", "ciphertext")
        with self.assertRaises(ValueError):
            sign("invalid_key", self.plaintext)
        with self.assertRaises(ValueError):
            verify("invalid_key", self.plaintext, "signature")
            
    def test_long_input(self):
        """测试长文本"""
        long_text = "这是一段很长的测试文本" * 100
        ciphertext = encrypt(self.public_key, long_text)
        decrypted = decrypt(self.private_key, ciphertext)
        self.assertEqual(decrypted, long_text)
        
        signature = sign(self.private_key, long_text)
        result = verify(self.public_key, long_text, signature)
        self.assertEqual(result, 'valid')

if __name__ == '__main__':
    unittest.main() 