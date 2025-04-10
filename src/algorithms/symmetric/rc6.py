from Crypto.Util.number import bytes_to_long, long_to_bytes
import struct

# RC6常量
P32 = 0xB7E15163
Q32 = 0x9E3779B9
ROUNDS = 20

def rotate_left(value, shift):
    """循环左移"""
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def rotate_right(value, shift):
    """循环右移"""
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF

def process_key(key, required_length=16):
    """处理密钥，确保长度正确"""
    if key is None:
        raise ValueError("密钥不能为空")
    if isinstance(key, str):
        if not key.strip():
            raise ValueError("密钥不能为空")
        key_bytes = key.encode()
    else:
        if not key:
            raise ValueError("密钥不能为空")
        key_bytes = key
    if len(key_bytes) < required_length:
        return key_bytes.ljust(required_length, b'\0')
    return key_bytes[:required_length]

def key_schedule(key):
    """密钥扩展"""
    # 初始化常量
    P = 0xB7E15163
    Q = 0x9E3779B9
    
    # 将密钥转换为32位整数数组
    c = len(key) // 4
    L = [0] * c
    for i in range(c):
        L[i] = struct.unpack('>I', key[i*4:(i+1)*4])[0]
    
    # 初始化S数组
    S = [0] * 44
    S[0] = P
    for i in range(1, 44):
        S[i] = (S[i-1] + Q) & 0xFFFFFFFF
    
    # 混合密钥
    A = B = i = j = 0
    v = 3 * max(c, 44)
    for s in range(v):
        A = S[i] = rotate_left((S[i] + A + B) & 0xFFFFFFFF, 3)
        B = L[j] = rotate_left((L[j] + A + B) & 0xFFFFFFFF, (A + B) & 0x1F)
        i = (i + 1) % 44
        j = (j + 1) % c
    
    return S

def encrypt(key, plaintext):
    """RC6加密
    
    Args:
        key: 密钥，16字节
        plaintext: 明文，字符串或字节
    Returns:
        加密后的密文，十六进制字符串
    """
    try:
        # 处理密钥
        key = process_key(key)
        
        # 处理明文
        if plaintext is None:
            raise ValueError("明文不能为空")
        if isinstance(plaintext, str):
            if not plaintext.strip():
                raise ValueError("明文不能为空")
            plaintext = plaintext.encode('utf-8')
        elif not plaintext:
            raise ValueError("明文不能为空")
            
        # 密钥扩展
        S = key_schedule(key)
        
        # 填充明文到16字节的倍数
        if len(plaintext) % 16 != 0:
            plaintext = plaintext.ljust(len(plaintext) + (16 - len(plaintext) % 16), b'\0')
        
        # 加密
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            # 将16字节分组转换为4个32位整数
            A = struct.unpack('>I', plaintext[i:i+4])[0]
            B = struct.unpack('>I', plaintext[i+4:i+8])[0]
            C = struct.unpack('>I', plaintext[i+8:i+12])[0]
            D = struct.unpack('>I', plaintext[i+12:i+16])[0]
            
            # 加密轮函数
            B = (B + S[0]) & 0xFFFFFFFF
            D = (D + S[1]) & 0xFFFFFFFF
            for j in range(1, 21):
                t = rotate_left((B * (2*B + 1)) & 0xFFFFFFFF, 5)
                u = rotate_left((D * (2*D + 1)) & 0xFFFFFFFF, 5)
                A = (rotate_left(A ^ t, u & 0x1F) + S[2*j]) & 0xFFFFFFFF
                C = (rotate_left(C ^ u, t & 0x1F) + S[2*j + 1]) & 0xFFFFFFFF
                A, B, C, D = B, C, D, A
            A = (A + S[42]) & 0xFFFFFFFF
            C = (C + S[43]) & 0xFFFFFFFF
            
            # 将结果转换回字节
            ciphertext += struct.pack('>I', A) + struct.pack('>I', B) + \
                         struct.pack('>I', C) + struct.pack('>I', D)
        
        return ciphertext.hex()
    except Exception as e:
        raise ValueError(f"RC6加密失败: {str(e)}")

def decrypt(key, ciphertext):
    """RC6解密
    
    Args:
        key: 密钥，16字节
        ciphertext: 密文，十六进制字符串
    Returns:
        解密后的明文，字符串
    """
    try:
        # 处理密钥
        key = process_key(key)
        
        # 处理密文
        if ciphertext is None:
            raise ValueError("密文不能为空")
        if not isinstance(ciphertext, str):
            raise ValueError("密文必须是十六进制字符串")
        if not ciphertext.strip():
            raise ValueError("密文不能为空")
            
        # 密钥扩展
        S = key_schedule(key)
        
        # 将十六进制字符串转换为字节
        ciphertext = bytes.fromhex(ciphertext)
        
        # 解密
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            # 将16字节分组转换为4个32位整数
            A = struct.unpack('>I', ciphertext[i:i+4])[0]
            B = struct.unpack('>I', ciphertext[i+4:i+8])[0]
            C = struct.unpack('>I', ciphertext[i+8:i+12])[0]
            D = struct.unpack('>I', ciphertext[i+12:i+16])[0]
            
            # 解密轮函数
            C = (C - S[43]) & 0xFFFFFFFF
            A = (A - S[42]) & 0xFFFFFFFF
            for j in range(20, 0, -1):
                A, B, C, D = D, A, B, C
                u = rotate_left((D * (2*D + 1)) & 0xFFFFFFFF, 5)
                t = rotate_left((B * (2*B + 1)) & 0xFFFFFFFF, 5)
                C = rotate_right((C - S[2*j + 1]) & 0xFFFFFFFF, t & 0x1F) ^ u
                A = rotate_right((A - S[2*j]) & 0xFFFFFFFF, u & 0x1F) ^ t
            D = (D - S[1]) & 0xFFFFFFFF
            B = (B - S[0]) & 0xFFFFFFFF
            
            # 将结果转换回字节
            plaintext += struct.pack('>I', A) + struct.pack('>I', B) + \
                        struct.pack('>I', C) + struct.pack('>I', D)
        
        # 去除填充
        plaintext = plaintext.rstrip(b'\0')
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"RC6解密失败: {str(e)}") 