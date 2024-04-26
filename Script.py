from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
import os
import argparse

class SecureRSA:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.load_keypair()

    def load_keypair(self):
        if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
            with open("private_key.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            with open("public_key.pem", "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )

    def generate_keypair(self):
        if self.private_key is not None and self.public_key is not None:
            print("Key pair already exists.")
            return

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.private_key = private_key
        self.public_key = private_key.public_key()
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("public_key.pem", "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Key pair generated successfully.")

    def encrypt_file(self, file_path, output_path):
        if self.public_key is None:
            print("Please generate key pair first.")
            return

        symmetric_key = os.urandom(32) 

        with open(file_path, "rb") as f:
            file_content = f.read()

        cipher = AES.new(symmetric_key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(file_content)

        encrypted_symmetric_key = self.public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(output_path, "wb") as f:
            f.write(encrypted_symmetric_key)
            f.write(cipher.nonce)
            f.write(tag)
            f.write(cipher_text)

        print("File encrypted successfully.")

    def decrypt_file(self, file_path, output_path):
        if self.private_key is None:
            print("Please generate key pair first.")
            return

        with open(file_path, "rb") as f:
            encrypted_symmetric_key = f.read(256)  
            nonce = f.read(16)  
            tag = f.read(16)  
            cipher_text = f.read()

        symmetric_key = self.private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
        plain_text = cipher.decrypt_and_verify(cipher_text, tag)

        with open(output_path, "wb") as f:
            f.write(plain_text)

        print("File decrypted successfully.")

def main():
    parser = argparse.ArgumentParser(description="Python based RSA Encryption and Decryption Tool")
    parser.add_argument("--generate-keypair", action="store_true", help="Generate RSA key pair")
    parser.add_argument("--encrypt-file", type=str, help="Path to the file to be encrypted")
    parser.add_argument("--output-file-encrypt", type=str, help="Path to save the encrypted file")
    parser.add_argument("--decrypt-file", type=str, help="Path to the file to be decrypted")
    parser.add_argument("--output-file-decrypt", type=str, help="Path to save the decrypted file")
    args = parser.parse_args()

    secure_rsa = SecureRSA()

    if args.generate_keypair:
        secure_rsa.generate_keypair()

    if args.encrypt_file and args.output_file_encrypt:
        secure_rsa.encrypt_file(args.encrypt_file, args.output_file_encrypt)

    if args.decrypt_file and args.output_file_decrypt:
        secure_rsa.decrypt_file(args.decrypt_file, args.output_file_decrypt)

if __name__ == "__main__":
    main()
