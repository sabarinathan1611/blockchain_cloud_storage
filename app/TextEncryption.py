from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import os

class CryptoRSA:
    def __init__(self, public_key_path, private_key_path):
        with open(public_key_path, 'rb') as f:
            self.public_key = RSA.import_key(f.read())
        with open(private_key_path, 'rb') as f:
            self.private_key = RSA.import_key(f.read())

    def encrypt_message(self, message, salt):
        session_key = get_random_bytes(16)
        


        # Prepend the salt to the message
        message_with_salt = salt + message.encode()

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        ciphertext = cipher_aes.encrypt(self.pad_data(message_with_salt))

        # Return the encrypted session key, iv, and ciphertext
        return base64.b64encode(encrypted_session_key), base64.b64encode(cipher_aes.iv), base64.b64encode(ciphertext)

    def decrypt_message(self, encrypted_session_key_b64, iv_b64, ciphertext_b64,salt):
       
        encrypted_session_key = base64.b64decode(encrypted_session_key_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted_message_with_salt = self.unpad_data(cipher_aes.decrypt(ciphertext))

        # Remove the salt from the decrypted message
        # print("Salt : ",salt)
        # print("decrypted_message_with_salt :",decrypted_message_with_salt)
        # print("Type of decrypted_message_with_salt :",type(decrypted_message_with_salt))
        # print("Salt: ",decrypted_message_with_salt[ :len(salt)])


        if salt == decrypted_message_with_salt[:len(salt)]:
            decrypted_message = decrypted_message_with_salt[len(salt):]


        return decrypted_message.decode()

    def pad_data(self, data):
        block_size = AES.block_size
        padding = block_size - (len(data) % block_size)
        return data + bytes([padding] * padding)

    def unpad_data(self, data):
        padding = data[-1]
        return data[:-padding]

def generate_key_pair(public_key_path, private_key_path):
    # Check if files exist
    if not os.path.exists(public_key_path) or not os.path.exists(private_key_path):
        # Generate key pair
        key = RSA.generate(2048)

        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(key.publickey().export_key(format='DER'))  # Save in DER format

        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(key.export_key(format='DER'))  # Save in DER format
        
        print("Public and private key pair generated and saved successfully.")
    else:
        print("Key pair files already exist.")

def text_encryption(public_key_path, private_key_path, message,salt):

    rsa_instance = CryptoRSA(public_key_path, private_key_path)

 
    encrypted_session_key, iv, ciphertext = rsa_instance.encrypt_message(message,salt)

    
    return encrypted_session_key, iv, ciphertext

def text_decryption(public_key_path, private_key_path, encrypted_session_key, iv, ciphertext,salt):
    # Initialize RSA instance
    rsa_instance = CryptoRSA(public_key_path, private_key_path)

    # Decrypt the message
    decrypted_message = rsa_instance.decrypt_message(encrypted_session_key, iv, ciphertext,salt)
    # print("Decrypted Message:", decrypted_message)
    
    return decrypted_message

# Example usage:
# public_key_path = 'public_key.der'
# private_key_path = 'private_key.der'
# message = "This is a secret message"

# # Encrypt the message
# encrypted_session_key, iv, ciphertext = text_encryption(public_key_path, private_key_path, message)

# # Decrypt the message
# decrypted_message = text_decryption(public_key_path, private_key_path, encrypted_session_key, iv, ciphertext)
"""
1st Time :
    real 0m4.310s
    user 0m1.776s
    sys  0m0.294s
    
2nd Time : 
    real 0m0.466s
    user 0m0.288s
    sys  0m0.153s


"""