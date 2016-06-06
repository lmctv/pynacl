from __future__ import print_function
import nacl.generichash, base64, binascii

D = binascii.unhexlify('000102')
D_prime = binascii.unhexlify('030405')
D_dbl_prime = binascii.unhexlify('060708')
K = binascii.unhexlify('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
H = binascii.unhexlify('33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1')
H_prime = binascii.unhexlify('6044540d560853eb1c57df0077dd381094781cdb9073e5b1b3d3f6c7829e12066bbaca96d989a690de72ca3133a83652ba284a6d62942b271ffa2620c9e75b1f')
H__dbl_prime = binascii.unhexlify('60fe3c4535e1b59d9a61ea8500bfac41a69dffb1ceadd9aca323e9a625b64da5763bad7226da02b9c8c4f1a5de140ac5a6c1124e4f718ce0b28ea47393aa6637')

print(len(H), len(K))

if __name__ == '__main__':
    # dgst = nacl.generichash.blake2b_digest(D,digest_size=len(H),key=K)
    dgst = nacl.generichash.generichash_digest(D,digest_size=len(H),key=K)
    print(len(H), dgst, binascii.hexlify(H))

    blake = nacl.generichash.blake2b(digest_size=len(H), key=K)
    blake.update(D)
    bl2 = blake.copy()
    print('*', binascii.hexlify(blake.digest()))
    bl2.update(D_prime)
    print('**', binascii.hexlify(bl2.digest()))
    print('?', binascii.hexlify(blake.digest()))

