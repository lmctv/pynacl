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

from six import integer_types

import nacl.exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure


BYTES_MIN = lib.crypto_kdf_blake2b_bytes_min()
BYTES_MAX = lib.crypto_kdf_blake2b_bytes_max()
CONTEXTBYTES = lib.crypto_kdf_blake2b_contextbytes()
KEYBYTES = lib.crypto_kdf_blake2b_keybytes()


def crypto_kdf_blake2b_derive_from_key(sk_len, sk_id, ctx, key):
    """Derive a subkey from a **cryptographically strong** master key.
    The contruction **must not be used** with low-entropy input byte
    sequences.

    :param sk_len:
    :type sk_len: int
    :param sk_id:
    :type sk_id: int
    :param ctx:
    :type ctx: bytes
    :param key:
    :type key: bytes

    """
    exc.ensure(isinstance(sk_len, integer_types),
               raising=TypeError)
    exc.ensure(isinstance(sk_id, integer_types),
               raising=TypeError)
    exc.ensure(isinstance(ctx, bytes),
               raising=TypeError)
    exc.ensure(isinstance(key, bytes),
               raising=TypeError)

    if sk_len < BYTES_MIN or sk_len > BYTES_MAX:
        raise exc.ValueError(("Requested length for derived key"
                              " must be comprised between"
                              " {0} and {1}").format(
                                                     BYTES_MIN,
                                                     BYTES_MAX
                                                     )
                             )
    if len(ctx) != CONTEXTBYTES:
        raise exc.ValueError(("Context length must be"
                              " exactly {0} bytes").format(CONTEXTBYTES)
                             )
    if len(key) != KEYBYTES:
        raise exc.ValueError(("Key length must be"
                              " exactly {0} bytes").format(KEYBYTES)
                             )

    subkey = ffi.new("unsigned char[]", sk_len)

    rc = lib.crypto_kdf_blake2b_derive_from_key(subkey, sk_len,
                                                sk_id, ctx, key)

    ensure(rc == 0, raising=exc.RuntimeError)
    return ffi.buffer(subkey, sk_len)[:]
