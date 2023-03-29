# This is an example of EC-based ElGamal encryption and decryption
# Curves (P-256 P-384 P-521 Ed25519 Ed448) integrated in Crypto.PublicKey.ECC library are available
# EC ElGamal Encryption Principle：C1,C2 = (k * P, m + k*h)
# EC ElGamal decryption principle：m = C2 + (- x*C1)
from Crypto.PublicKey import ECC
from Crypto.Random import random
import nacl.utils
import nacl.secret
import nacl.encoding
import nacl.exceptions
import nacl.hash

# ---- Step 1: Generate Keys ----

# Available curves：P-256 P-384 P-521 Ed25519 Ed448
ec = 'P-256'
# p - order
p = ECC._curves[ec].order
# P - base point
P = ECC.EccPoint(x=ECC._curves[ec].Gx, y=ECC._curves[ec].Gy, curve=ec)

# x - ElGamal private key
x:int = random.randint(0, int(p))
# h - ElGamal public key
h:ECC.EccPoint = x* P

message = 'Some secret message to be encrypted!'
encoded_message = bytes(message, 'utf-8')

# key_point is the symmetric key
r = random.randint(0, int(p))
key_point = r * P

# ---- Step 2: Encrypt Message ----

# Encrypt plaintext messages with symmetic key to get the `encrypted`
def _key_bytes_from_point(p: ECC.EccPoint) -> bytes:
    key_point_byte_length = (int(p.x).bit_length() + 7) // 8
    point_bytes = int(p.x).to_bytes(key_point_byte_length, byteorder='big')
    return point_bytes

point_bytes = _key_bytes_from_point(key_point)
symmetric_key = nacl.hash.blake2b(point_bytes,
                                  digest_size=nacl.secret.SecretBox.KEY_SIZE,
                                  encoder=nacl.encoding.RawEncoder)
box = nacl.secret.SecretBox(symmetric_key)
encrypted = box.encrypt(encoded_message)

# Encrypting symmetric keys with ElGamal to get `C1`, `C2`
k = random.randint(0, int(p))

C1 = k * P
Q = h
kQ = k * Q
C2 = key_point + kQ

# ---- Step 3: Decrypt Message ----

# Decrypt `C1``, `C2` with ElGamal to get the symmetric key dec_elgamal
dec_tmp = x*C1
dec_elgamal = C2 + (- dec_tmp)

assert dec_elgamal == key_point # Confirm


# Decrypt `encrypted` with symmetric key and get the message
point_bytes = _key_bytes_from_point(dec_elgamal)
key = nacl.hash.blake2b(point_bytes,
                        digest_size=nacl.secret.SecretBox.KEY_SIZE,
                        encoder=nacl.encoding.RawEncoder)
box = nacl.secret.SecretBox(key)
encoded_plaintext = box.decrypt(encrypted)
print(str(encoded_plaintext, 'utf-8'))