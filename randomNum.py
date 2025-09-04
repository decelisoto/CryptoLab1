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
print('salt: ',salt.hex())
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
print('key: ',key.hex())
print('iv: ',iv.hex())