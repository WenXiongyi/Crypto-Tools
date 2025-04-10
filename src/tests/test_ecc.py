import unittest
from src.algorithms.public_key.ecc import (
    generate_key, encrypt, decrypt,
    generate_ecdsa_key, ecdsa_sign, ecdsa_verify
)

class TestECC(unittest.TestCase):
    def setUp(self):
        self.plaintext = "这是一段测试文本"
        self.keys = generate_key()
        self.ecdsa_keys = generate_ecdsa_key()
        
    def test_generate_key(self):
        """测试ECC密钥生成"""
        self.assertIn('privatekey', self.keys)
        self.assertIn('publickey', self.keys)
        self.assertIsInstance(self.keys['privatekey'], str)
        self.assertIsInstance(self.keys['publickey'], str)
        
    def test_encrypt_decrypt(self):
        """测试ECC加密解密"""
        # 加密
        ciphertext = encrypt(self.keys['publickey'], self.plaintext)
        self.assertIsInstance(ciphertext, str)
        self.assertNotEqual(ciphertext, self.plaintext)
        
        # 解密
        decrypted = decrypt(self.keys['privatekey'], ciphertext)
        self.assertEqual(decrypted, self.plaintext)
        
    def test_ecdsa_sign_verify(self):
        """测试ECDSA签名验证"""
        # 生成签名
        signature = ecdsa_sign(self.ecdsa_keys['privatekey'], self.plaintext)
        self.assertIsInstance(signature, str)
        
        # 验证
        result = ecdsa_verify(self.ecdsa_keys['publickey'], self.plaintext, signature)
        self.assertEqual(result, 'valid')
        
        # 验证错误签名
        # 修改签名的最后一个字节
        signature_bytes = bytes.fromhex(signature)
        wrong_signature_bytes = signature_bytes[:-1] + bytes([(signature_bytes[-1] + 1) % 256])
        wrong_signature = wrong_signature_bytes.hex()
        
        result = ecdsa_verify(self.ecdsa_keys['publickey'], self.plaintext, wrong_signature)
        self.assertEqual(result, 'invalid')
        
    def test_invalid_key(self):
        """测试无效密钥"""
        with self.assertRaises(Exception):
            encrypt("invalid_key", self.plaintext)
            
    def test_invalid_ciphertext(self):
        """测试无效密文"""
        with self.assertRaises(Exception):
            decrypt(self.keys['privatekey'], "invalid_ciphertext")

if __name__ == '__main__':
    unittest.main() 