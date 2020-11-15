from base64 import b64decode
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder


def decrypt(ciphertext, key, iv):
    global encoder
    aes = AES.new(key.encode("utf8"), AES.MODE_CBC, iv.encode("utf8"))
    pad_text = aes.decrypt(ciphertext)
    return pad_text


if __name__ == '__main__':
    encoder = PKCS7Encoder()

    ciphertext = b64decode("id9DKqgpF5fy819hI4Bc2Q==")
    key = 'fqIhyykbTjNQ2QdQlBOISw=='
    iv = '8119745113154120'

    print("Ciphertext: '%s'" % ciphertext)
    print("Key: '%s'" % key)
    print("IV: '%s'" % iv)

    decrypted = decrypt(ciphertext, key, iv)
    print("decrypted: '%s'" % decrypted)
