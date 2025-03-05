from quantcrypt.kem import Kyber
from Crypto.Cipher import AES
import base64
class FileCryptoKyber:
    def __init__(self, public_key_path, private_key_path):
        self.kem = Kyber()

        # Load or generate keys
        try:
            with open(public_key_path, 'rb') as f:
                self.public_key = f.read()
            with open(private_key_path, 'rb') as f:
                self.private_key = f.read()
        except FileNotFoundError:
            # Generate keys if not found
            self.public_key, self.private_key = self.kem.keygen()
            with open(public_key_path, 'wb') as f:
                f.write(self.public_key)
            with open(private_key_path, 'wb') as f:
                f.write(self.private_key)

    def encrypt_file(self, file_data, salt):
        # Encapsulate shared secret using the public key
        encrypted_session_key, shared_secret = self.kem.encaps(self.public_key)

        # Add salt to the data
        data_with_salt = salt + file_data

        # Encrypt data using AES with the shared secret
        cipher_aes = AES.new(shared_secret[:16], AES.MODE_CBC)
        padded_data = self.pad_data(data_with_salt)
        ciphertext = cipher_aes.encrypt(padded_data)

        return encrypted_session_key, cipher_aes.iv, ciphertext

    def decrypt_file(self, encrypted_session_key, iv, ciphertext, salt):
        # Decapsulate shared secret using the private key
        shared_secret = self.kem.decaps(self.private_key, encrypted_session_key)

        # Decrypt data using AES
        cipher_aes = AES.new(shared_secret[:16], AES.MODE_CBC, iv)
        decrypted_data_with_salt = cipher_aes.decrypt(ciphertext)

        # Validate and remove salt
        if decrypted_data_with_salt[:len(salt)] != salt:
            raise ValueError("Salt verification failed.")
        return self.unpad_data(decrypted_data_with_salt[len(salt):])

    @staticmethod
    def pad_data(data):
        block_size = AES.block_size
        padding = block_size - (len(data) % block_size)
        return data + bytes([padding] * padding)

    @staticmethod
    def unpad_data(data):
        padding = data[-1]
        return data[:-padding]
