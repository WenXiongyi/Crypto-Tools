import unittest
from src.algorithms.symmetric.sm4 import encrypt, decrypt

class TestSM4(unittest.TestCase):
    def setUp(self):
        self.key = "testkey1234567890"
        self.plaintext = "这是一段测试文本"
        
    def test_encrypt_decrypt(self):
        """测试加密解密"""
        # 加密
        ciphertext = encrypt(self.key, self.plaintext)
        self.assertIsInstance(ciphertext, str)
        
        # 解密
        decrypted = decrypt(self.key, ciphertext)
        self.assertEqual(decrypted, self.plaintext)
        
    def test_empty_input(self):
        """测试空输入"""
        with self.assertRaises(ValueError):
            encrypt("", self.plaintext)
        with self.assertRaises(ValueError):
            encrypt(self.key, "")
            
    def test_invalid_key(self):
        """测试无效密钥"""
        with self.assertRaises(ValueError):
            encrypt(None, self.plaintext)
            
    def test_invalid_ciphertext(self):
        """测试无效密文"""
        with self.assertRaises(ValueError):
            decrypt(self.key, "invalid_base64")
            
    def test_byte_input(self):
        """测试字节输入"""
        plaintext_bytes = self.plaintext.encode('utf-8')
        ciphertext = encrypt(self.key, plaintext_bytes)
        decrypted = decrypt(self.key, ciphertext)
        self.assertEqual(decrypted, self.plaintext)
        
    def test_long_input(self):
        """测试长文本"""
        long_text = "这是一段很长的测试文本" * 100
        ciphertext = encrypt(self.key, long_text)
        decrypted = decrypt(self.key, ciphertext)
        self.assertEqual(decrypted, long_text)

if __name__ == '__main__':
    unittest.main() 