import base64
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESCipher(object):

    iv_size = algorithms.AES.block_size // 8

    def __init__(self, key, mode=modes.CBC):
        self.mode = mode
        self.aes = algorithms.AES(key)

    def encrypt(self, cleartext):
        iv = secrets.token_bytes(self.iv_size)

        cipher = Cipher(self.aes,
                        self.mode(iv),
                        default_backend()).encryptor()

        if self.mode == modes.CBC:
            cleartext = self._pad(cleartext)

        return base64.urlsafe_b64encode(iv + cipher.update(cleartext) + cipher.finalize())

    def decrypt(self, ciphertext):
        msg = base64.urlsafe_b64decode(ciphertext)
        iv = msg[:self.iv_size]

        cipher = Cipher(self.aes,
                        self.mode(iv),
                        default_backend()).decryptor()

        msg = cipher.update(msg[self.iv_size:]) + cipher.finalize()

        if self.mode == modes.CBC:
            msg = self._unpad(msg)

        return msg

    def _pad(self, msg):
        """append PKCS padding"""
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        return padder.update(msg) + padder.finalize()

    def _unpad(self, msg):
        """remov PKCS padding"""
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(msg) + unpadder.finalize()
