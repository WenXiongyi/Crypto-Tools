import base64

def base64_encode(plaintext):
    """Base64编码"""
    return base64.b64encode(plaintext.encode()).decode('utf-8')

def base64_decode(ciphertext):
    """Base64解码"""
    return base64.b64decode(ciphertext).decode('utf-8')

def utf8_encode(plaintext):
    """UTF-8编码"""
    try:
        return plaintext.encode('utf-8').decode('utf-8')
    except UnicodeError:
        raise ValueError("无效的UTF-8编码")

def utf8_decode(ciphertext):
    """UTF-8解码"""
    try:
        if isinstance(ciphertext, str):
            return ciphertext
        return ciphertext.decode('utf-8')
    except UnicodeError:
        raise ValueError("无效的UTF-8编码") 