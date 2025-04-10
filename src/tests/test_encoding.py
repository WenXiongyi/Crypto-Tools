import unittest
from src.algorithms.encoding.encoding import (
    base64_encode, base64_decode,
    utf8_encode, utf8_decode
)

class TestEncoding(unittest.TestCase):
    def setUp(self):
        self.plaintext = "这是一段测试文本"
        
    def test_base64(self):
        """测试Base64编码解码"""
        # 编码
        encoded = base64_encode(self.plaintext)
        self.assertIsInstance(encoded, str)
        self.assertNotEqual(encoded, self.plaintext)
        
        # 解码
        decoded = base64_decode(encoded)
        self.assertEqual(decoded, self.plaintext)
        
    def test_utf8(self):
        """测试UTF-8编码解码"""
        # 编码
        encoded = utf8_encode(self.plaintext)
        self.assertIsInstance(encoded, str)
        self.assertEqual(encoded, self.plaintext)
        
        # 解码
        decoded = utf8_decode(encoded)
        self.assertEqual(decoded, self.plaintext)
        
    def test_invalid_base64(self):
        """测试无效Base64"""
        with self.assertRaises(Exception):
            base64_decode("invalid_base64")
            
    def test_invalid_utf8(self):
        """测试无效的UTF-8编码"""
        # 使用无效的UTF-8字节序列
        invalid_bytes = b'\xff\xfe'
        with self.assertRaises(ValueError):
            utf8_decode(invalid_bytes)

if __name__ == '__main__':
    unittest.main() 