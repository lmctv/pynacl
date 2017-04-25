# Copyright 2017 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import binascii

import pytest

import nacl.bindings
import nacl.exceptions as exc


MASTER_KEY = (b'\x00\x01\x02\x03\x04\x05\x06\x07'
              b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
              b'\x10\x11\x12\x13\x14\x15\x16\x17'
              b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f')

SKLEN = nacl.bindings.crypto_kdf_blake2b_BYTES_MAX

CTX = b'KDF test'

EXP = (
        (b"a0c724404728c8bb95e5433eb6a9716171144d61efb23e74b873fcbeda51d807"
         b"1b5d70aae12066dfc94ce943f145aa176c055040c3dd73b0a15e36254d450614"),
        (b"02507f144fa9bf19010bf7c70b235b4c2663cc00e074f929602a5e2c10a78075"
         b"7d2a3993d06debc378a90efdac196dd841817b977d67b786804f6d3cd585bab5"),
        (b"1944da61ff18dc2028c3578ac85be904931b83860896598f62468f1cb5471c6a"
         b"344c945dbc62c9aaf70feb62472d17775ea5db6ed5494c68b7a9a59761f39614"),
        (b"131c0ca1633ed074986215b264f6e0474f362c52b029effc7b0f75977ee89cc9"
         b"5d85c3db87f7e399197a25411592beeeb7e5128a74646a460ecd6deb4994b71e"),
        (b"a7023a0bf9be245d078aed26bcde0465ff0cc0961196a5482a0ff4ff8b401597"
         b"1e13611f50529cb408f5776b14a90e7c3dd9160a22211db64ff4b5c0b9953680"),
        (b"50f49313f3a05b2e565c13feedb44daa675cafd42c2b2cf9edbce9c949fbfc3f"
         b"175dcb738671509ae2ea66fb85e552394d479afa7fa3affe8791744796b94176"),
        (b"13b58d6d69780089293862cd59a1a8a4ef79bb850e3f3ba41fb22446a7dd1dc4"
         b"da4667d37b33bf1225dcf8173c4c349a5d911c5bd2db9c5905ed70c11e809e3b"),
        (b"15d44b4b44ffa006eeceeb508c98a970aaa573d65905687b9e15854dec6d49c6"
         b"12757e149f78268f727660dedf9abce22a9691feb20a01b0525f4b47a3cf19db"),
        (b"9aebba11c5428ae8225716369e30a48943be39159a899f804e9963ef78822e18"
         b"6c21fe95bb0b85e60ef03a6f58d0b9d06e91f79d0ab998450b8810c73ca935b4"),
        (b"70f9b83e463fb441e7a4c43275125cd5b19d8e2e4a5d179a39f5db10bbce745a"
         b"199104563d308cf8d4c6b27bbb759ded232f5bdb7c367dd632a9677320dfe416"),
      )


def get_expected_skids_and_keys():
    _xp = [x for x in enumerate(EXP, 0)]
    return _xp


@pytest.mark.parametrize(("sk_id", "expected"),
                         get_expected_skids_and_keys()
                         )
def test_kdf(sk_id, expected):
    res = nacl.bindings.crypto_kdf_blake2b_derive_from_key(SKLEN, sk_id,
                                                           CTX, MASTER_KEY)
    assert res == binascii.unhexlify(expected)


def test_too_short_master_key():
    with pytest.raises(exc.ValueError):
        nacl.bindings.crypto_kdf_blake2b_derive_from_key(SKLEN, 2,
                                                         CTX,
                                                         MASTER_KEY[:-1])


def test_too_short_derived_key():
    with pytest.raises(exc.ValueError):
        nacl.bindings.crypto_kdf_blake2b_derive_from_key(1, 3,
                                                         CTX,
                                                         MASTER_KEY[:-1])


def test_too_short_context():
    with pytest.raises(exc.ValueError):
        nacl.bindings.crypto_kdf_blake2b_derive_from_key(SKLEN, 3,
                                                         CTX[:-1],
                                                         MASTER_KEY)
