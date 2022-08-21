from ecc.curve import Curve25519
from ecc.key import gen_keypair
from ecc.cipher import ElGamal

plaintext = b"Brigitha"
pri_key, pub_key = gen_keypair(Curve25519)
cipher_elg = ElGamal(Curve25519)
C1, C2 = cipher_elg.encrypt(plaintext, pub_key)

new_plaintext = cipher_elg.decrypt(pri_key, C1, C2)
print(plaintext)
print(C1)
print(C2)
print(new_plaintext)