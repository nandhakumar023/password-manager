import getpass
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import bcrypt

# Get the password from the user
password = getpass.getpass()


# ...
# salt_1 = bcrypt.gensalt()
with open("hash.txt", "rb") as file:
    salt_1 = file.read(29)
    file.seek(30)
    encrypted_data = file.read()


# with open("hash.txt", "rb") as file:
#     salt_1 = file.read()


hashed_passwd = bcrypt.hashpw(password.encode(), salt_1)
print("Hashed password111: ", hashed_passwd)

# Hash the password
# hashed_password = hashlib.sha256(password.encode()).digest()
# print("Hashed password: ", hashed_password)

# Generate a 16-byte salt value
# salt = secrets.token_bytes(16)
# print("Salt: ", salt)

# Derive a key from the hashed password
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt_1,
    iterations=100000
)
key = kdf.derive(password.encode())

# Set the encryption algorithm and mode
algorithmeee = algorithms.AES(key)
iv = os.urandom(16)  # Generate a random 16-byte IV
mode = modes.CBC(iv)

# Create a cipher context
cipher = Cipher(algorithmeee, mode, backend=default_backend())

# Encode data
def encode(data):
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

# Decode data
def decode(encrypted_data):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithmeee, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

# Example usage:
data = b"Hello, World!"
# encrypted_data = encode(data)
print("Encrypted data before file:", encrypted_data)
print("salt before: ", salt_1)

# with open("hash.txt", "wb") as file:
#     file.write(salt_1)
#     file.seek(30)
#     file.write(encrypted_data)

# with open("hash.txt", "rb") as file:
#     salt_1 = file.read(29)
#     file.seek(30)
#     encrypted_data = file.read()

print(len(salt_1))
print("Encrypted data after file:", encrypted_data)
print("salt after: ", salt_1)
decrypted_data = decode(encrypted_data)
print("Decrypted data:", decrypted_data)