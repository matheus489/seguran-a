# Arquivo para implementar criptografia simétrica e assimétrica
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

class SymmetricEncryption:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data

class AsymmetricEncryption:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

    def encrypt(self, data):
        cipher = PKCS1_OAEP.new(self.public_key)
        ciphertext = cipher.encrypt(data)
        return ciphertext

    def decrypt(self, ciphertext):
        cipher = PKCS1_OAEP.new(self.key)
        data = cipher.decrypt(ciphertext)
        return data 
