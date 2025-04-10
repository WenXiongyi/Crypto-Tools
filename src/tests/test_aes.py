import unittest
from src.algorithms.symmetric.aes import encrypt, decrypt

class TestAES(unittest.TestCase):
    def setUp(self):
        self.key = "testkey1234567890"
        self.plaintext = "这是一段测试文本"
        
    def test_encrypt_decrypt(self):
        """测试AES加密解密"""
        # 加密
        ciphertext = encrypt(self.key, self.plaintext)
        self.assertIsInstance(ciphertext, str)
        self.assertNotEqual(ciphertext, self.plaintext)
        
        # 解密
        decrypted = decrypt(self.key, ciphertext)
        self.assertEqual(decrypted, self.plaintext)
        
    def test_invalid_key(self):
        """测试无效密钥"""
        with self.assertRaises(Exception):
            encrypt("", self.plaintext)
            
    def test_invalid_ciphertext(self):
        """测试无效密文"""
        with self.assertRaises(Exception):
            decrypt(self.key, "invalid_ciphertext")

if __name__ == '__main__':
    unittest.main() 