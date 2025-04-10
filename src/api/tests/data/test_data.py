"""测试数据模块"""

# AES测试数据
AES_TEST_DATA = {
    "key": "test_key_16bytes",
    "plaintext": "test_plaintext",
    "ciphertext": "test_ciphertext"
}

# RSA测试数据
RSA_TEST_DATA = {
    "public_key": "test_public_key",
    "private_key": "test_private_key",
    "plaintext": "test_plaintext",
    "signature": "test_signature"
}

# SHA256测试数据
SHA256_TEST_DATA = {
    "plaintext": "test_plaintext",
    "hash": "test_hash"
}

# 所有测试数据
TEST_DATA = {
    "aes": AES_TEST_DATA,
    "rsa": RSA_TEST_DATA,
    "sha256": SHA256_TEST_DATA
} 