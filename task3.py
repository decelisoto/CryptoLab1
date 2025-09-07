# task3.py
# Encrypt infile.txt -> outfile.txt, then decrypt outfile.txt -> restored.txt.
# Verbose terminal output for screenshots (mode, salt, sizes, block-by-block ciphertext).
# Change MODE to "ECB" or "CBC" and run again for separate screenshots.

import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ===== Config (edit if needed) =====
IN_PATH   = "infile.txt"
ENC_PATH  = "outfile.txt"     # will be overwritten with CIPHERTEXT
DEC_PATH  = "restored.txt"
MODE      = "CBC"             # set to "ECB" or "CBC"
KEY_PW    = b"password"       # password used to derive KEY (PBKDF2)
IV_PW     = b"hello"          # password used to derive IV  (PBKDF2)
SHOW_SECRETS = False          # set True if you want to print key/iv hex (for lab only)
CHUNK     = 64 * 1024         # streaming chunk size
# ===================================

BACKEND   = default_backend()
SALT_LEN  = 16
KEY_LEN   = 16                # 128-bit AES
ITER      = 100_000
AES_BLK   = 16

def _derive_key_iv(key_pw: bytes, iv_pw: bytes, salt: bytes):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=ITER, backend=BACKEND)
    idf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=ITER, backend=BACKEND)
    key = kdf.derive(key_pw)
    iv  = idf.derive(iv_pw)
    return key, iv

def _cipher(mode: str, key: bytes, iv: bytes):
    mode = mode.upper()
    return Cipher(algorithms.AES(key), modes.ECB() if mode == "ECB" else modes.CBC(iv), backend=BACKEND)

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(131072), b""):
            h.update(chunk)
    return h.hexdigest()

def _print_blocks(label: str, data: bytes, block=AES_BLK):
    print(label)
    for i in range(0, len(data), block):
        print(f"  block {i//block:02d}: {data[i:i+block].hex()}")

def encrypt_file(in_path: str, out_path: str, mode: str):
    print("=== ENCRYPT ===")
    print(f"Mode: {mode}")
    print(f"Input : {in_path}")
    print(f"Output: {out_path}")

    salt = os.urandom(SALT_LEN)
    key, iv = _derive_key_iv(KEY_PW, IV_PW, salt)

    if SHOW_SECRETS:
        print(f"salt: {salt.hex()}")
        print(f"key : {key.hex()}")
        print(f"iv  : {iv.hex()}")
    else:
        print(f"salt: {salt.hex()} (key/iv hidden)")

    cipher = _cipher(mode, key, iv)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    total_in = 0
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        # Write header: [salt][mode_marker]
        fout.write(salt)
        fout.write(b"\x01" if mode.upper() == "ECB" else b"\x02")

        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                break
            total_in += len(chunk)
            padded = padder.update(chunk)
            if padded:
                fout.write(encryptor.update(padded))

        tail_pad = padder.finalize()
        fout.write(encryptor.update(tail_pad) + encryptor.finalize())

    pt_size  = os.path.getsize(in_path)
    ct_size  = os.path.getsize(out_path)
    print(f"Plaintext size : {pt_size} bytes")
    print(f"Ciphertext size: {ct_size} bytes (includes 16-byte salt + 1-byte mode)")
    print("Encryption complete.\n")

def decrypt_file(in_path: str, out_path: str):
    print("=== DECRYPT ===")
    print(f"Input : {in_path}")
    print(f"Output: {out_path}")

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        salt  = fin.read(SALT_LEN)
        mbyte = fin.read(1)
        enc_mode = "ECB" if mbyte == b"\x01" else "CBC"

        key, iv = _derive_key_iv(KEY_PW, IV_PW, salt)
        cipher = _cipher(enc_mode, key, iv)
        decryptor = cipher.decryptor()
        unpadder  = padding.PKCS7(128).unpadder()

        # For block-by-block ciphertext printing, read the *rest* of file to a buffer once (lab-scale).
        ciphertext = fin.read()
        # Print blocks so ECB/CBC differences are obvious:
        _print_blocks(f"Ciphertext blocks ({enc_mode}):", ciphertext)

        # Now actually decrypt the buffered ciphertext in streaming style
        total_ct = 0
        for i in range(0, len(ciphertext), CHUNK):
            chunk = ciphertext[i:i+CHUNK]
            total_ct += len(chunk)
            pt_padded = decryptor.update(chunk)
            if pt_padded:
                fout.write(unpadder.update(pt_padded))

        tail = decryptor.finalize()
        fout.write(unpadder.update(tail) + unpadder.finalize())

    print(f"Decryption complete. Processed {total_ct} ciphertext bytes.\n")

if __name__ == "__main__":
    # 1) Encrypt infile.txt -> outfile.txt
    encrypt_file(IN_PATH, ENC_PATH, MODE)

    # 2) Decrypt outfile.txt -> restored.txt
    decrypt_file(ENC_PATH, DEC_PATH)

    # 3) Compare
    h_in  = _sha256(IN_PATH)
    h_dec = _sha256(DEC_PATH)
    print("=== VERIFY ===")
    print(f"SHA256({IN_PATH})  = {h_in}")
    print(f"SHA256({DEC_PATH}) = {h_dec}")
    print(f"Match: {h_in == h_dec}")
