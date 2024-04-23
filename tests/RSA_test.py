import unittest
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from hashlib import sha256
from basisClasses.RSA import RSA

class TestRSA(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = RSA.generate_rsa_key_pair()
        self.test_file_path = "test_file.txt"
        self.hashed_file_path = "test_hashed_file.txt"

    def tearDown(self):
        if os.path.exists(self.test_file_path):
            os.remove(self.test_file_path)
        if os.path.exists(self.hashed_file_path):
            os.remove(self.hashed_file_path)

    def test_generate_rsa_key_pair(self):
        self.assertIsInstance(self.private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(self.public_key, rsa.RSAPublicKey)

    def test_save_load_private_key(self):
        RSA.save_private_key('test_private_key.pem', self.private_key)
        loaded_private_key = RSA.load_private_key('test_private_key.pem')
        # Compare key properties
        self.assertEqual(self.private_key.private_numbers(), loaded_private_key.private_numbers())

    def test_save_load_public_key(self):
        RSA.save_public_key('test_public_key.pem', self.public_key)
        loaded_public_key = RSA.load_public_key('test_public_key.pem')
        # Compare key properties
        self.assertEqual(self.public_key.public_numbers(), loaded_public_key.public_numbers())

    def test_save_load_file(self):
        with open(self.test_file_path, 'w') as f:
            f.write("Test file content")
        with open(self.test_file_path, 'rb') as file_to_save:
            RSA.save_file(file_to_save, 'test_saved_file.txt')
        with open('test_saved_file.txt', 'rb') as saved_file:
            loaded_file_content = saved_file.read()
        with open(self.test_file_path, 'rb') as original_file:
            original_file_content = original_file.read()
        self.assertEqual(original_file_content, loaded_file_content)

    def test_encrypt_decrypt_file(self):
        with open(self.test_file_path, 'w') as f:
            f.write("Test file content")
        with open(self.test_file_path, 'rb') as file_to_encrypt:
            encrypted_content = RSA.encrypt_file(file_to_encrypt, self.public_key)
        with open('encrypted_file.txt', 'wb') as encrypted_file:
            encrypted_file.write(encrypted_content)
        with open('encrypted_file.txt', 'rb') as file_to_decrypt:
            decrypted_content = RSA.decrypt_file(file_to_decrypt, self.private_key)
        with open(self.test_file_path, 'rb') as original_file:
            original_content = original_file.read()
        self.assertEqual(original_content, decrypted_content)

    def test_integrity_verification(self):
        with open(self.test_file_path, 'w') as f:
            f.write("Test file content")
        with open(self.test_file_path, 'rb') as file_to_hash:
            file_content = file_to_hash.read()
        hashed_content = sha256(file_content).digest()
        with open(self.hashed_file_path, 'wb') as hashed_file:
            hashed_file.write(hashed_content)
        with open(self.hashed_file_path, 'rb') as hashed_file:
            hash_result = RSA.integrity_verification(file_content, self.hashed_file_path)
        self.assertEqual(hash_result, "Checks")


if __name__ == '__main__':
    unittest.main()
