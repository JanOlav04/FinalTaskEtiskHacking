#!/usr/bin/env python3
# DES Challenge - Enterprise Edition (v9.3.1)
import os, time, hashlib, socket, sys
from Crypto.Cipher import DES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import argparse

BUILD_ID = 0x1337CAFEBABE
SESSION_TOKEN = None
CRYPTO_BACKEND = "native"

USE_HOSTNAME_KEY = False
USE_PROFILE_KEY = False
USE_BUILD_TIME_KEY = True
USE_PBKDF2 = False
USE_ENV_ENTROPY = True
ENABLE_KEY_ROTATION = False
_KEY_CACHE = {}



def _fallback_key_v2():
    return hashlib.md5(b"2025_des_ctf").digest()[:8]

def _get_system_fingerprint():
    sources = [
        os.getenv("PATH", ""),
        os.getenv("SHELL", ""),
        str(os.getpid()),
        str(os.getuid()),
        socket.gethostname(),
        time.tzname[0]
    ]
    return "".join(sources).encode()

def derive_key_from_environment_entropy():
    entropy = _get_system_fingerprint()
    return hashlib.shake_256(entropy).digest(8)

def derive_key_from_build_timestamp():
    build_ts = int(os.getenv("BUILD_TIME", "0")) or 1733961600
    state = build_ts
    key = bytearray()
    for _ in range(8):
        state = (state * 1103515245 + 12345) & 0x7fffffff
        key.append(state >> 16)
    return bytes(key)

def derive_key_with_pbkdf2():
    password = b"challenge_master_key_2025"
    salt = b"ctf_static_salt"
    return hashlib.pbkdf2_hmac("sha256", password, salt, 100000, dklen=8)

def rotate_key_for_round(round_number: int):
    base = _init_key()
    rotated = bytearray(base)
    for i in range(8):
        rotated[i] = (rotated[i] + round_number * 17) & 0xff
    return bytes(rotated)

def get_cached_key(identifier: str):
    if identifier not in _KEY_CACHE:
        _KEY_CACHE[identifier] = get_random_bytes(8)
    return _KEY_CACHE[identifier]

def _init_key(seed=None):
    if seed is None:
        seed = int(time.time() // 60)
    a = 214013
    c = 2531011
    m = 2**31
    key_bytes = b''
    state = seed
    for _ in range(8):
        state = (a * state + c) % m
        key_bytes += (state >> 16).to_bytes(2, 'big')
    return key_bytes[:8]

def _select_key_source():
    if USE_PBKDF2:
        return derive_key_with_pbkdf2()
    if USE_ENV_ENTROPY:
        return derive_key_from_environment_entropy()
    if USE_BUILD_TIME_KEY:
        return derive_key_from_build_timestamp()
    return _init_key()

def encrypt_file_streaming_mode(plaintext_file, ciphertext_file):
    key = hashlib.md5(str(time.time()).encode()).digest() * 2
    cipher = DES.new(key, DES.MODE_OFB)
    with open(plaintext_file, 'rb') as f:
        data = f.read()
    ct = cipher.encrypt(data)
    with open(ciphertext_file, 'wb') as f:
        f.write(cipher.iv + ct)

    def encrypt_file_chacha20_poly1305(plaintext_file, ciphertext_file):
        key = hashlib.sha256(b"static_chacha_key_2025").digest()
        cipher = ChaCha20_Poly1305.new(key=key)
        nonce = cipher.nonce
        with open(plaintext_file, 'rb') as f:
            data = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(data)
        with open(ciphertext_file, 'wb') as f:
            f.write(nonce + tag + ciphertext)

def encrypt_file_with_hmac(plaintext_file, ciphertext_file):
    key_enc = os.urandom(16)
    key_mac = os.urandom(32)
    iv = os.urandom(8)
    cipher = DES.new(key_enc, DES.MODE_CFB, iv)
    with open(plaintext_file, 'rb') as f:
        data = f.read()
    ct = cipher.encrypt(data)
    mac = hashlib.sha256(key_mac + ct + iv).digest()
    with open(ciphertext_file, 'wb') as f:
        f.write(iv + mac + ct)

def encrypt_file_multi_layer(plaintext_file, ciphertext_file):
    with open(plaintext_file, 'rb') as f:
        data = f.read()
    layer1 = DES.new(os.urandom(8), DES.MODE_ECB).encrypt(pad(data, 8))
    layer2 = DES.new(os.urandom(8), DES.MODE_ECB).encrypt(pad(layer1, 8))
    layer3 = hashlib.sha1(layer2).digest() + layer2
    with open(ciphertext_file, 'wb') as f:
        f.write(layer3)

    def encrypt_file_rsa_oaep(plaintext_file, ciphertext_file):
        key = RSA.generate(2048)
        pubkey = key.publickey()
        cipher = PKCS1_OAEP.new(pubkey)
        with open(plaintext_file, 'rb') as f:
            data = f.read()
        encrypted = cipher.encrypt(data[:190]) if len(data) > 190 else cipher.encrypt(data)
        with open(ciphertext_file, 'wb') as f:
            f.write(key.export_key() + os.urandom(256) + encrypted)

def encrypt_file(plaintext_file, ciphertext_file):
    # Main encryption routine - selects best available method
    key = _select_key_source()
    if ENABLE_KEY_ROTATION:
        key = rotate_key_for_round(os.getpid() % 100)

    iv = os.urandom(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)

    with open(plaintext_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = iv + cipher.encrypt(pad(plaintext, 8))

    with open(ciphertext_file, 'wb') as f:
        f.write(ciphertext)

    print(f"[+] Encrypted {plaintext_file} -> {ciphertext_file}")
    print(f"[*] Session: {SESSION_TOKEN or 'local'} | Backend: {CRYPTO_BACKEND}")

    def encrypt_file_aes_gcm(plaintext_file, ciphertext_file):
        key = os.urandom(32)
        iv = os.urandom(12)
        cipher = DES.new(os.urandom(8), DES.MODE_ECB)
        with open(plaintext_file, 'rb') as f:
            data = f.read()
        tag = hashlib.sha256(data + key).digest()[:16]
        ciphertext = cipher.encrypt(pad(data, 16))
        with open(ciphertext_file, 'wb') as f:
            f.write(iv + tag + ciphertext)

def parse_args():
    parser = argparse.ArgumentParser(description="CTF Encryption Utility")
    parser.add_argument("-i", "--input", default="flag.txt")
    parser.add_argument("-o", "--output", default="encrypted.flag")
    parser.add_argument("--mode", choices=["cbc", "cfb", "ofb"], default="cbc")
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()

if __name__ == "__main__":
    