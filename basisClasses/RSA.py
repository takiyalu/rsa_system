from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from hashlib import sha256


class RSA:

    @staticmethod
    # Generate Keys
    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    # Save private key into the specified file
    def save_private_key(path, private_key):
        with open(path, 'wb') as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    @staticmethod
    # Save public key into the specified file
    def save_public_key(path, public_key):
        with open(path, 'wb') as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    # load my current key
    @staticmethod
    def load_private_key(path=None, file=None):
        if file:
            return serialization.load_pem_private_key(file.read(), password=None)
        else:
            with open(path, 'rb') as f:
                return serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )

    @staticmethod
    def load_public_key(path=None, file=None):
        if file:
            return serialization.load_pem_public_key(file.read())
        else:
            with open(path, 'rb') as f:
                return serialization.load_pem_public_key(f.read())

    @staticmethod
    def save_file(file, path):
        with open(path, 'wb') as sf:
            sf.write(file.read())

    @staticmethod
    def encrypt_file(file, public_key):
        plain_text = file.read()
        with open('hashed_file', 'wb') as hf:
            hf.write(sha256(plain_text).digest())
        ciphertext = public_key.encrypt(
            plain_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(ciphertext)
        return ciphertext

    @staticmethod
    def decrypt_file(file, private_key):
        plaintext = private_key.decrypt(
            file.read(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(plaintext)
        return plaintext


    @staticmethod
    def integrity_verification(decrypted_txt, hashed_file_path):
        with open(hashed_file_path, 'rb') as hf:
            hashtxt = hf.read()
            hashed_input = sha256(decrypted_txt).digest()
            print(hashtxt)
            print(hashed_input)
            if hashtxt == hashed_input:
                return "Checks"
            else:
                return 'Corrupted File'