import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from encodings.base64_codec import base64_encode

backend = default_backend()
salt = os.urandom(16)
print('salt: ', salt.hex())

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
    backend=backend)

idf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
    backend=backend)

passwd = b'password'
ivval = b'hello'
key = kdf.derive(passwd)
iv = idf.derive(ivval)
print('key: ', key.hex())
print('iv: ', iv.hex())

# create a cipher, get an encryptor
cipher = Cipher(
    algorithm=algorithms.AES(key),
    mode=modes.CBC(iv),
    backend=backend)
encryptor = cipher.encryptor()

# Create some dummy data and encrypt it
mydata = b'University of Miami'
print(mydata)

padder = padding.PKCS7(128).padder()
mydata_pad = padder.update(mydata) + padder.finalize()
print(mydata_pad.hex())

ciphertext = encryptor.update(mydata_pad) + encryptor.finalize()
print(ciphertext.hex())

# Get the decryptor, decrypt the ciphertext and print the result for comparison
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
print(plaintext.hex())

# Try the cipher in ECB mode
cipher_ecb = Cipher(
    algorithm=algorithms.AES(key),
    mode=modes.ECB(),
    backend=backend)
encryptor_ecb = cipher_ecb.encryptor()

# Encrypt the same block repeated twice
repeated_data = b'REPEAT_BLOCK_16!' * 2  # 16-byte block repeated twice
print("Repeated data:", repeated_data)

padder_ecb = padding.PKCS7(128).padder()
repeated_data_pad = padder_ecb.update(repeated_data) + padder_ecb.finalize()
print("Padded repeated data:", repeated_data_pad.hex())

ciphertext_ecb = encryptor_ecb.update(repeated_data_pad) + encryptor_ecb.finalize()

# Print ciphertext block-by-block
block_size = 16  # AES block size
print("ECB ciphertext blocks:")
for i in range(0, len(ciphertext_ecb), block_size):
    print(ciphertext_ecb[i:i + block_size].hex())

# Decrypt the ECB ciphertext
decryptor_ecb = cipher_ecb.decryptor()
plaintext_ecb_padded = decryptor_ecb.update(ciphertext_ecb) + decryptor_ecb.finalize()

# Unpad the plaintext to get the original data
unpadder_ecb = padding.PKCS7(128).unpadder()
plaintext_ecb = unpadder_ecb.update(plaintext_ecb_padded) + unpadder_ecb.finalize()
print("Decrypted ECB plaintext:", plaintext_ecb)