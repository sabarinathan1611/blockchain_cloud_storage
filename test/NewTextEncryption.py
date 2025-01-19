from quantcrypt.kem import Kyber
from Crypto.Cipher import AES
import base64

class CryptoKyber:
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

    def encrypt_message(self, message, salt):
        # Encapsulate shared secret using the public key
        encrypted_session_key, shared_secret = self.kem.encaps(self.public_key)

        # Add salt to the message
        message_with_salt = salt + message.encode()

        # Encrypt message using AES with the shared secret
        cipher_aes = AES.new(shared_secret[:16], AES.MODE_CBC)
        ciphertext = cipher_aes.encrypt(self.pad_data(message_with_salt))

        # Return encrypted session key, AES IV, and ciphertext
        return base64.b64encode(encrypted_session_key), base64.b64encode(cipher_aes.iv), base64.b64encode(ciphertext)

    def decrypt_message(self, encrypted_session_key_b64, iv_b64, ciphertext_b64, salt):
        # Decode base64-encoded inputs
        encrypted_session_key = base64.b64decode(encrypted_session_key_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # Decapsulate shared secret using the private key
        shared_secret = self.kem.decaps(self.private_key, encrypted_session_key)

        # Decrypt message using AES with the shared secret
        cipher_aes = AES.new(shared_secret[:16], AES.MODE_CBC, iv)
        decrypted_message_with_salt = self.unpad_data(cipher_aes.decrypt(ciphertext))

        # Validate salt and extract original message
        if decrypted_message_with_salt[:len(salt)] != salt:
            raise ValueError("Salt verification failed.")
        return decrypted_message_with_salt[len(salt):].decode()

    def pad_data(self, data):
        block_size = AES.block_size
        padding = block_size - len(data) % block_size
        return data + bytes([padding] * padding)

    def unpad_data(self, data):
        padding = data[-1]
        return data[:-padding]


def text_encryption(public_key_path, private_key_path, message, salt):
    kyber_instance = CryptoKyber(public_key_path, private_key_path)
    encrypted_key, iv, ciphertext = kyber_instance.encrypt_message(message, salt)
    return encrypted_key, iv, ciphertext


def text_decryption(encrypted_key, iv, ciphertext, salt, public_key_path, private_key_path):
    kyber_instance = CryptoKyber(public_key_path, private_key_path)
    decrypted_message = kyber_instance.decrypt_message(encrypted_key, iv, ciphertext, salt)
    return decrypted_message


if __name__ == '__main__':
    salt = b"unique_salt_value"
    message = "Post-quantum secure message"
    public_key_path = "./public_key.der"
    private_key_path = "./private_key.der"

    # Encrypt the message
    encrypted_key, iv, ciphertext = text_encryption(public_key_path, private_key_path, message, salt)
    print("Encrypted Message:", ciphertext)

    # Decrypt the message
    decrypted_message = text_decryption(encrypted_key, iv, ciphertext, salt, public_key_path, private_key_path)
    print("Decrypted Message:", decrypted_message)

    assert message == decrypted_message
