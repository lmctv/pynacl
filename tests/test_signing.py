# Copyright 2013 Donald Stufft and individual contributors
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

from utils import assert_equal, assert_not_equal, read_crypto_test_vectors

from nacl.bindings import crypto_sign_PUBLICKEYBYTES, crypto_sign_SEEDBYTES
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SignedMessage, SigningKey, VerifyKey
from nacl.utils import PyNaclDeprecated


def tohex(b):
    return binascii.hexlify(b).decode('ascii')


def ed25519_known_answers():
    # Known answers taken from: http://ed25519.cr.yp.to/python/sign.input
    # hex-encoded fields on each input line: sk||pk, pk, msg, signature||msg
    # known answer fields: sk, pk, msg, signature, signed
    DATA = "ed25519"
    lines = read_crypto_test_vectors(DATA, delimiter=b':')
    return [(x[0][:64],   # secret key
             x[1],        # public key
             x[2],        # message
             x[3][:128],  # signature
             x[3],        # signed message
             )
            for x in lines]


class TestSigningKey:
    def test_initialize_with_generate(self):
        SigningKey.generate()

    def test_wrong_length(self):
        with pytest.raises(ValueError):
            SigningKey(b"")

    def test_bytes(self):
        k = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
        assert bytes(k) == b"\x00" * crypto_sign_SEEDBYTES

    def test_equal_keys_are_equal(self):
        k1 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
        k2 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
        assert_equal(k1, k1)
        assert_equal(k1, k2)

    def test_equal_keys_have_equal_hashes(self):
        k1 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
        k2 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
        assert hash(k1) == hash(k2)
        assert id(k1) != id(k2)

    @pytest.mark.parametrize('k2', [
        b"\x00" * crypto_sign_SEEDBYTES,
        SigningKey(b"\x01" * crypto_sign_SEEDBYTES),
        SigningKey(b"\x00" * (crypto_sign_SEEDBYTES - 1) + b"\x01"),
    ])
    def test_different_keys_are_not_equal(self, k2):
        k1 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
        assert_not_equal(k1, k2)

    @pytest.mark.parametrize("hseed", [
        b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ])
    def test_initialization_with_seed(self, hseed):
        seed = binascii.unhexlify(hseed)
        SigningKey(seed)

    @pytest.mark.parametrize(
        ("hseed", "_public_key", "message", "signature", "expected"),
        ed25519_known_answers()
    )
    def test_message_signing(self, hseed, _public_key,
                             message, signature, expected):
        seed = binascii.unhexlify(hseed)
        signing_key = SigningKey(seed)
        signed = signing_key.sign(
            binascii.unhexlify(message),
        )

        assert signed == binascii.unhexlify(expected)
        assert signed.message == binascii.unhexlify(message)
        assert signed.signature == binascii.unhexlify(signature)

    @pytest.mark.parametrize("hseed", [
        b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ])
    def test_deprecation_of_encoder_parameter(self, hseed):
        with pytest.warns(PyNaclDeprecated):
            SigningKey(hseed,
                       encoder=HexEncoder,
                       )
        with pytest.warns(PyNaclDeprecated):
            SigningKey(hseed,
                       HexEncoder,
                       )
        sk = SigningKey.generate()
        unsigned = b"A test message!"
        with pytest.warns(PyNaclDeprecated):
            sk.sign(unsigned,
                    encoder=HexEncoder)
        with pytest.warns(PyNaclDeprecated):
            sk.sign(unsigned,
                    HexEncoder)

    @pytest.mark.parametrize("hseed", [
        b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ])
    def test_raising_on_excess_encoder_parameter(self, hseed):
        with pytest.raises(TypeError):
            SigningKey(hseed,
                       HexEncoder,
                       HexEncoder,
                       )
        sk = SigningKey.generate()
        unsigned = b"A test message!"
        with pytest.raises(TypeError):
            sk.sign(unsigned,
                    HexEncoder,
                    HexEncoder)


class TestVerifyKey:
    def test_wrong_length(self):
        with pytest.raises(ValueError):
            VerifyKey(b"")

    def test_bytes(self):
        k = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        assert bytes(k) == b"\x00" * crypto_sign_PUBLICKEYBYTES

    def test_equal_keys_are_equal(self):
        k1 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        k2 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        assert_equal(k1, k1)
        assert_equal(k1, k2)

    def test_equal_keys_have_equal_hashes(self):
        k1 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        k2 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        assert hash(k1) == hash(k2)
        assert id(k1) != id(k2)

    @pytest.mark.parametrize('k2', [
        b"\x00" * crypto_sign_PUBLICKEYBYTES,
        VerifyKey(b"\x01" * crypto_sign_PUBLICKEYBYTES),
        VerifyKey(b"\x00" * (crypto_sign_PUBLICKEYBYTES - 1) + b"\x01"),
    ])
    def test_different_keys_are_not_equal(self, k2):
        k1 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        assert_not_equal(k1, k2)

    @pytest.mark.parametrize(
        ("_seed", "hpublic_key", "hmessage", "hsignature", "hsigned"),
        ed25519_known_answers()
    )
    def test_valid_signed_message(
            self, _seed, hpublic_key, hmessage, hsignature, hsigned):
        public_key = binascii.unhexlify(hpublic_key)
        key = VerifyKey(public_key)

        signed = binascii.unhexlify(hsigned)
        message = binascii.unhexlify(hmessage)
        signature = binascii.unhexlify(hsignature)

        assert key.verify(signed) == message
        assert key.verify(message, signature) == message

    def test_invalid_signed_message(self):
        skey = SigningKey.generate()
        smessage = skey.sign(b"A Test Message!")
        signature, message = smessage.signature, b"A Forged Test Message!"

        # Small sanity check
        assert skey.verify_key.verify(smessage)

        with pytest.raises(BadSignatureError):
            skey.verify_key.verify(message, signature)

        with pytest.raises(BadSignatureError):
            forged = SignedMessage(signature + message)
            skey.verify_key.verify(forged)

    def test_key_conversion(self):
        keypair_seed = (b"421151a459faeade3d247115f94aedae"
                        b"42318124095afabe4d1451a559faedee")
        signing_key = SigningKey(binascii.unhexlify(keypair_seed))
        verify_key = signing_key.verify_key

        private_key = bytes(signing_key.to_curve25519_private_key())
        public_key = bytes(verify_key.to_curve25519_public_key())

        assert tohex(private_key) == ("8052030376d47112be7f73ed7a019293"
                                      "dd12ad910b654455798b4667d73de166")

        assert tohex(public_key) == ("f1814f0e8ff1043d8a44d25babff3ced"
                                     "cae6c22c3edaa48f857ae70de2baae50")

    def test_deprecation_of_encoder_parameter(self):
        sk = SigningKey.generate()
        unsigned = b"A test message!"
        with pytest.warns(PyNaclDeprecated):
            hsigned = sk.sign(unsigned, encoder=HexEncoder)
        hpub = HexEncoder.encode(bytes(sk.verify_key))
        with pytest.warns(PyNaclDeprecated):
            VerifyKey(hpub,
                      encoder=HexEncoder,
                      )
        with pytest.warns(PyNaclDeprecated):
            VerifyKey(hpub,
                      HexEncoder,
                      )
        with pytest.warns(PyNaclDeprecated):
            sk.verify_key.verify(hsigned,
                                 encoder=HexEncoder)
        with pytest.warns(PyNaclDeprecated):
            sk.verify_key.verify(hsigned.message,
                                 hsigned.signature,
                                 HexEncoder)

    def test_raising_on_excess_encoder_parameter(self):
        sk = SigningKey.generate()
        unsigned = b"A test message!"
        with pytest.warns(PyNaclDeprecated):
            hsigned = sk.sign(unsigned, encoder=HexEncoder)
        hpub = HexEncoder.encode(bytes(sk.verify_key))
        with pytest.raises(TypeError):
            VerifyKey(hpub,
                      HexEncoder,
                      HexEncoder,
                      )
        with pytest.raises(TypeError):
            sk.verify_key.verify(hsigned.message,
                                 hsigned.signature,
                                 HexEncoder,
                                 HexEncoder)


def check_type_error(expected, f, *args):
    with pytest.raises(TypeError) as e:
        f(*args)
    assert expected in str(e)


def test_wrong_types():
    sk = SigningKey.generate()

    check_type_error("SigningKey must be created from a 32 byte seed",
                     SigningKey, 12)
    check_type_error("SigningKey must be created from a 32 byte seed",
                     SigningKey, sk)
    check_type_error("SigningKey must be created from a 32 byte seed",
                     SigningKey, sk.verify_key)

    check_type_error("VerifyKey must be created from 32 bytes",
                     VerifyKey, 13)
    check_type_error("VerifyKey must be created from 32 bytes",
                     VerifyKey, sk)
    check_type_error("VerifyKey must be created from 32 bytes",
                     VerifyKey, sk.verify_key)
