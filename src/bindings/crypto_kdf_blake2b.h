/* Copyright 2017 Donald Stufft and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * #define crypto_kdf_blake2b_CONTEXTBYTES 8
 * #define crypto_kdf_blake2b_KEYBYTES 32
 */


size_t crypto_kdf_blake2b_bytes_min(void);
size_t crypto_kdf_blake2b_bytes_max(void);
size_t crypto_kdf_blake2b_contextbytes(void);
size_t crypto_kdf_blake2b_keybytes(void);

int crypto_kdf_blake2b_derive_from_key(unsigned char *subkey, size_t subkey_len,
                                       uint64_t subkey_id,
                                       const char ctx[8],
                                       const unsigned char key[32]);
