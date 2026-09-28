#!/usr/bin/env python3
"""Checks an implementation against the vectors used in the specification.

Run: python3 spec/check_vectors.py

The script derives everything itself — HKDF, the fingerprint, the signed
material — and compares it with the vector file. If your implementation
produces the same values, it agrees with this one.
"""
import hashlib, hmac, json, base64, os, sys

def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t = b"", b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]

here = os.path.dirname(os.path.abspath(__file__))
v = json.load(open(os.path.join(here, "guest-protocol-vectors.json"), encoding="utf-8"))

seed = hkdf_sha256(v["user_key"].encode(), b"entrixy-guest-sign-v1")
key_id = hashlib.sha256(v["user_key"].encode()).hexdigest()

ok = True
def check(name, got, want):
    global ok
    good = got == want
    ok = ok and good
    print(f"  {name:22s} {'ok' if good else 'MISMATCH'}")
    if not good:
        print(f"    got:      {got}\n    expected: {want}")

check("seed", seed.hex(), v["seed"])
check("key_id", key_id, v["key_id"])

material = (f'v1.{v["key_id"]}.{v["request"]["ts"]}.{v["request"]["nonce"]}.'
            f'{v["request"]["endpoint"]}.'
            + hashlib.sha256(v["request"]["body"].encode()).hexdigest())
check("request material", material, v["request"]["material"])

hello = (f'v1.{v["key_id"]}.{v["hello"]["material"].split(".")[2]}.'
         f'{v["hello"]["material"].split(".")[3]}.guest_hello.'
         + hashlib.sha256(v["hello"]["device_fp"].encode()).hexdigest())
check("hello material", hello, v["hello"]["material"])

# The pair a handset settles with: the same derivation, salted with the
# device fingerprint and with its own info string.
dp = v.get("device_pair")
if dp:
    dseed = hkdf_sha256(v["user_key"].encode(), b"entrixy-guest-device-v1",
                        salt=dp["device_fp"].encode())
    check("device seed", dseed.hex(), dp["seed"])

print("\nThe Ed25519 signatures are verified with your own library: the public"
      " half is in sign_pub_hex, the expected signatures in the sig_b64 fields.")
sys.exit(0 if ok else 1)
