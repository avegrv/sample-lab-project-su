from Crypto.Cipher import AES
from base64 import b64encode, b64decode


def decrypt(cipherText, key, initializationVector):
    aes = AES.new(key.encode('utf8'), AES.MODE_CBC, initializationVector.encode('utf8'))
    return aes.decrypt(cipherText)


if __name__ == '__main__':
    cipherText = b64decode('pzMwuWciCt05C/AVR2rT8Q==')
    key = 'MjEzMTQ5Mjg5NQ=='
    initializationVector = '8119745113154120'

    plainText = decrypt(cipherText, key, initializationVector)
    print('Your pin code is ' + str(plainText))
