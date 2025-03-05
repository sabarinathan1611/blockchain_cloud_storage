import os
import base64
from Crypto.Cipher import AES
from dotenv import dotenv_values, set_key

class AESCipher:
    def __init__(self, env_path=".env"):
        self.env_path = env_path
        self.env_vars = dotenv_values(env_path)
        key_encoded = self.env_vars.get("KEY")
        iv_encoded = self.env_vars.get("IV")

        if key_encoded is None or iv_encoded is None:
            # Generate new key and IV if they are missing
            self.key_bytes = os.urandom(32)  
            self.iv_bytes = os.urandom(16)   
            
            
            set_key(self.env_path, "KEY", self.key_bytes.hex())
            set_key(self.env_path, "IV", self.iv_bytes.hex())
        else:
            
            self.key_bytes = bytes.fromhex(key_encoded)
            self.iv_bytes = bytes.fromhex(iv_encoded)

    def pad_data(self, data):
        # PKCS7 Padding
        pad_length = AES.block_size - (len(data) % AES.block_size)
        return data + bytes([pad_length] * pad_length)

    def unpad_data(self, padded_data):
        pad_length = padded_data[-1]
        return padded_data[:-pad_length]

    def encrypt_data(self, data):
        cipher = AES.new(self.key_bytes, AES.MODE_CBC, iv=self.iv_bytes)
        padded_data = self.pad_data(data.encode())
        ciphertext = cipher.encrypt(padded_data)
        return ciphertext

    def decrypt_data(self, ciphertext):
        cipher = AES.new(self.key_bytes, AES.MODE_CBC, self.iv_bytes)
        decrypted_data = cipher.decrypt(ciphertext)
        return self.unpad_data(decrypted_data).decode()

# Example usage
#aes_cipher = AESCipher()

# data = "12345678901234567890123ert6789012345678901234567890"
# encrypted_data = aes_cipher.encrypt_data(data)
# print("Encrypted data:", encrypted_data)
# print(len(encrypted_data))

# decrypted_data = aes_cipher.decrypt_data(encrypted_data)
# print("Decrypted data:", decrypted_data)
