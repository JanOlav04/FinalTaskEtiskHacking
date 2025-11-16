# Made this it own file to make it easier to navigate.
# Retry decryption attempts with corrected key derivation implementations.
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import hashlib, os, socket, time, datetime, re
from pathlib import Path

def _get_system_fingerprint():
    sources = [
        os.getenv("PATH", ""),
        os.getenv("SHELL", ""),
        str(os.getpid()),
        str(os.getuid()) if hasattr(os, "getuid") else "0",
        socket.gethostname(),
        time.tzname[0] if hasattr(time, "tzname") else ""
    ]
    return "".join(sources).encode()

def derive_key_from_environment_entropy():
    entropy = _get_system_fingerprint()
    return hashlib.shake_256(entropy).digest(8)

def _fallback_key_v2():
    return hashlib.md5(b"2025_des_ctf").digest()[:8]

def derive_key_from_build_timestamp(build_ts=None):
    build_ts = int(os.getenv("BUILD_TIME", "0")) or (build_ts if build_ts is not None else 1733961600)
    state = build_ts
    key = bytearray()
    for _ in range(8):
        state = (state * 1103515245 + 12345) & 0x7fffffff
        # append two-byte big-endian of (state >> 16)
        val = (state >> 16) & 0xffff
        key += val.to_bytes(2, 'big')
    return bytes(key[:8])

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

enc_path = Path("WanaSmile\encrypted.flag")
data = enc_path.read_bytes()
iv = data[:8]; ct = data[8:]
FLAG_RE = re.compile(rb'flag\{[^}]+\}', re.I)

candidates = {}

# try env entropy key
k_env = derive_key_from_environment_entropy()
# try fallback
k_fallback = _fallback_key_v2()
# try build timestamp default
k_build_default = derive_key_from_build_timestamp(None)

candidates_list = [('env_entropy', k_env), ('fallback_v2', k_fallback), ('build_ts_default', k_build_default)]
found = None

# try candidates first
for name,k in candidates_list:
    try:
        cipher = DES.new(k, DES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), 8)
        if FLAG_RE.search(pt):
            found = (name, None, k, pt); break
    except Exception:
        pass

if not found:
    # try _init_key for a window of seeds (minute seeds)
    now = int(time.time())
    # try seeds from now-10 days to now+1 day
    start = now - 10*24*3600
    end = now + 24*3600
    checked = 0
    for t in range(start, end, 60):  # step by 60 seconds => minute seeds
        seed = t // 60
        key = _init_key(seed)
        try:
            cipher = DES.new(key, DES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), 8)
            if FLAG_RE.search(pt):
                found = ('init_seed', seed, key, pt)
                break
        except Exception:
            pass
        checked += 1
        if checked % 10000 == 0:
            print("Checked", checked, "seeds...")

print("Tried", checked, "minute-seeds plus", len(candidates_list), "other candidates.")
if found:
    print("Found by:", found[0], "seed:", found[1])
    try:
        print("Plaintext:", found[3].decode())
    except:
        print(repr(found[3]))
    m = FLAG_RE.search(found[3])
    if m:
        print("FLAG:", m.group(0).decode())
else:
    print("No key found in tried ranges/candidates.")