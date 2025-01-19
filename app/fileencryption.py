from quantcrypt.kem import Kyber
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class CryptoBase:
    def __init__(self):
        self.kem = Kyber()

    def generate_key_pair(self, public_key_path, private_key_path):
        # Generate Kyber key pair
        public_key, private_key = self.kem.keygen()

        # Save keys to specified paths
        with open(public_key_path, 'wb') as pub_file:
            pub_file.write(public_key)
        with open(private_key_path, 'wb') as priv_file:
            priv_file.write(private_key)

    def load_key_from_file(self, filename):
        with open(filename, 'rb') as file:
            key = file.read()
        return key

    def generate_aes_key(self):
        return get_random_bytes(16)  # 128-bit AES key

class FileEncryption(CryptoBase):
    def encrypt_file(self, filename, public_key_path):
        # Load public key from file
        public_key = self.load_key_from_file(public_key_path)

        # Generate a random AES key
        aes_key = self.generate_aes_key()

        # Encrypt the file using AES
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)
        with open(filename, 'rb') as file:
            data = file.read()
        encrypted_data, tag = aes_cipher.encrypt_and_digest(data)

        # Encapsulate the AES key with Kyber
        encapsulated_key, shared_secret = self.kem.encaps(public_key)

        # Write encapsulated key, AES nonce, tag, and encrypted data to the file
        with open(filename, 'wb') as file:
            file.write(encapsulated_key)
            file.write(aes_cipher.nonce)
            file.write(tag)
            file.write(encrypted_data)

class FileDecryption(CryptoBase):
    def decrypt_file(self, input_filename, private_key_path):
        # Load private key from file
        private_key = self.load_key_from_file(private_key_path)

        # Read encapsulated key, nonce, tag, and encrypted data from the file
        with open(input_filename, 'rb') as file:
            encapsulated_key = file.read(800)  # Kyber encapsulated key size
            nonce = file.read(16)  # AES nonce size
            tag = file.read(16)   # AES tag size
            encrypted_data = file.read()

        # Decapsulate the AES key with Kyber
        shared_secret = self.kem.decaps(private_key, encapsulated_key)
        aes_key = shared_secret[:16]  # Use the first 16 bytes of the shared secret

        # Decrypt the data using AES
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = aes_cipher.decrypt_and_verify(encrypted_data, tag)

        # Write the decrypted data back to the file
        with open(input_filename, 'wb') as file:
            file.write(decrypted_data)

        return decrypted_data

# Example Usage
if __name__ == "__main__":
    filename = "example.txt"  # Replace with your file path
    public_key_path = "public_key.bin"
    private_key_path = "private_key.bin"

    # Initialize the encryption/decryption classes
    encryption = FileEncryption()
    decryption = FileDecryption()

    # Generate Kyber key pair and save to specified paths
    encryption.generate_key_pair(public_key_path, private_key_path)

    # Encrypt the file
    encryption.encrypt_file(filename, public_key_path)
    print(f"File {filename} encrypted successfully.")

    # Decrypt the file
    decrypted_data = decryption.decrypt_file(filename, private_key_path)
    print(f"File {filename} decrypted successfully.")
