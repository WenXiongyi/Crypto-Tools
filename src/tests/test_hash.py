import unittest
from src.algorithms.hash.hash import (
    sha3_hash,
    ripemd160_hash,
    hmac_sha1,
    hmac_sha256,
    pbkdf2_derive
)

class TestHash(unittest.TestCase):
    def setUp(self):
        self.plaintext = "这是一段测试文本"
        self.key = "test_key"
        self.salt = "test_salt"
        
    def test_sha3_hash(self):
        """测试SHA3哈希"""
        # 测试字符串输入
        hash1 = sha3_hash(self.plaintext)
        self.assertIsInstance(hash1, str)
        self.assertEqual(len(hash1), 64)  # SHA3-256输出64个十六进制字符
        
        # 测试字节输入
        hash2 = sha3_hash(self.plaintext.encode('utf-8'))
        self.assertEqual(hash1, hash2)
        
    def test_ripemd160_hash(self):
        """测试RIPEMD160哈希"""
        # 测试字符串输入
        hash1 = ripemd160_hash(self.plaintext)
        self.assertIsInstance(hash1, str)
        self.assertEqual(len(hash1), 40)  # RIPEMD160输出40个十六进制字符
        
        # 测试字节输入
        hash2 = ripemd160_hash(self.plaintext.encode('utf-8'))
        self.assertEqual(hash1, hash2)
        
    def test_hmac_sha1(self):
        """测试HMAC-SHA1"""
        # 测试字符串输入
        hash1 = hmac_sha1(self.key, self.plaintext)
        self.assertIsInstance(hash1, str)
        self.assertEqual(len(hash1), 40)  # SHA1输出40个十六进制字符
        
        # 测试字节输入
        hash2 = hmac_sha1(self.key.encode('utf-8'), self.plaintext.encode('utf-8'))
        self.assertEqual(hash1, hash2)
        
    def test_hmac_sha256(self):
        """测试HMAC-SHA256"""
        # 测试字符串输入
        hash1 = hmac_sha256(self.key, self.plaintext)
        self.assertIsInstance(hash1, str)
        self.assertEqual(len(hash1), 64)  # SHA256输出64个十六进制字符
        
        # 测试字节输入
        hash2 = hmac_sha256(self.key.encode('utf-8'), self.plaintext.encode('utf-8'))
        self.assertEqual(hash1, hash2)
        
    def test_pbkdf2_derive(self):
        """测试PBKDF2"""
        # 测试默认参数
        key1 = pbkdf2_derive(self.key, self.salt)
        self.assertIsInstance(key1, str)
        self.assertEqual(len(key1), 64)  # 32字节 = 64个十六进制字符
        
        # 测试自定义参数
        key2 = pbkdf2_derive(self.key, self.salt, iterations=5000, key_length=16)
        self.assertIsInstance(key2, str)
        self.assertEqual(len(key2), 32)  # 16字节 = 32个十六进制字符
        
        # 测试不同迭代次数产生不同的密钥
        key3 = pbkdf2_derive(self.key, self.salt, iterations=10001)
        self.assertNotEqual(key1, key3)
        
    def test_empty_input(self):
        """测试空输入"""
        with self.assertRaises(ValueError):
            sha3_hash("")
        with self.assertRaises(ValueError):
            ripemd160_hash("")
        with self.assertRaises(ValueError):
            hmac_sha1("", self.plaintext)
        with self.assertRaises(ValueError):
            hmac_sha256("", self.plaintext)
        with self.assertRaises(ValueError):
            pbkdf2_derive("", self.salt)
            
    def test_invalid_input(self):
        """测试无效输入"""
        with self.assertRaises(ValueError):
            sha3_hash(None)
        with self.assertRaises(ValueError):
            ripemd160_hash(None)
        with self.assertRaises(ValueError):
            hmac_sha1(None, self.plaintext)
        with self.assertRaises(ValueError):
            hmac_sha256(None, self.plaintext)
        with self.assertRaises(ValueError):
            pbkdf2_derive(None, self.salt)

if __name__ == '__main__':
    unittest.main() 