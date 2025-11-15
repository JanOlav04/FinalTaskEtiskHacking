from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

encrypted_flag = "Cm7ukyVEUFlJtaEZuK760Lb5dLlWCWCmaXZzhJ5KTB4mtQNWxgq5kbR6JtL886ZG"

class AESCipher:
    def __init__(self, key: str):
        if len(key) != 13:
            raise ValueError("Key must be exactly 13 characters.")

        key_bytes = key.encode('utf-8')

        salt = b'static_salt_123'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.key = kdf.derive(key_bytes)

    def encrypt(self, plaintext: str) -> str:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

        return base64.b64encode(iv + enc).decode()

    def decrypt(self, encrypted: str) -> str:
        raw = base64.b64decode(encrypted)
        iv = raw[:16]
        ct = raw[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor().update(ct) + cipher.decryptor().finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(dec) + unpadder.finalize()).decode()
    
def caesar_shift(s: str, shift: int) -> str:
    result = []
    for ch in s:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(ch)
    return "".join(result)


def try_all_keys(ciphertext):
    strings = ["IIK3100IIK310","IIK3100I1337", "IIK3100ABCDEF", "IIK3100XYZ123", "IIK3100FLAG12"]
    odd_rots = [i for i in range(1, 100) if i % 2 == 1]

    for string in strings:
        for rot in odd_rots:
            try:
                usedkey= caesar_shift(string, rot)
                cipher = AESCipher(usedkey)

                result = cipher.decrypt(ciphertext)

                if "flag{" in result:
                    print("\n[+] SUCCESS!")
                    print(f"Base string: {string}")
                    print(f"Rotation: {rot}")
                    print(f"Key: {usedkey}")
                    print(f"Flag: {result}")
                    return
            except Exception:
                pass

        print("No valid key found.")

ciphertext = encrypted_flag
try_all_keys(ciphertext)