import base64

def encode_algorithm(algorithm, plaintext):
    if algorithm == "Base64":
        return base64.b64encode(plaintext.encode()).decode('utf-8')
    elif algorithm == "UTF-8":
        return plaintext.encode('utf-8').decode('utf-8')

def decode_algorithm(algorithm, ciphertext):
    if algorithm == "Base64":
        return base64.b64decode(ciphertext).decode('utf-8')
    elif algorithm == "UTF-8":
        return ciphertext.encode('utf-8').decode('utf-8') 