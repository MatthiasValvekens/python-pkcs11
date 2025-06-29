"""
PKCS#11 DSA Tests
"""

import base64

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.util.dsa import (
    decode_dsa_domain_parameters,
    encode_dsa_domain_parameters,
)

from . import FIXME, TestCase, requires

DHPARAMS = base64.b64decode("""
MIIBHwKBgQD8jXSat2sk+j0plaMn51AVYBWEyWee3ui3llRUckVceDILsjVdBs1tXCDhU7WC+VZZ
u6ujBHZONiXcQTZ6P/jhnYlSyjEoBTf7GntlbjeASm63XYzTt4E5i7u1RI6TmEIRj6VTrM5m5DFP
fDQ+fflAJzm0phT38gYE5xfe3mmCDQIVAMIMNr/4lufeH46EGKQXVnvtJBAZAoGBANxCIKAfh1/v
MvI/2s7S1ESGuwvmvbFWpxW3gNXvyO2mWjfHC3sQrwm3qED0R71n9bIL6VqRK+tBEy6VkR+lKifA
8rPnZvADPNBhRLhgDc4JuwYinRJSUPd1iZxJCbumfscr3Fp1XuUnCcMRkWqWr7rGEUP+ht+AeXpo
ouQbj2Vq
""")


class DSATests(TestCase):
    @requires(Mechanism.DSA_PARAMETER_GEN)
    @FIXME.nfast  # returns Function Failed
    def test_generate_params(self):
        parameters = self.session.generate_domain_parameters(KeyType.DSA, 1024)
        self.assertIsInstance(parameters, pkcs11.DomainParameters)
        self.assertEqual(parameters[Attribute.PRIME_BITS], 1024)

        encode_dsa_domain_parameters(parameters)

    @requires(Mechanism.DSA_KEY_PAIR_GEN, Mechanism.DSA_SHA1)
    def test_generate_keypair_and_sign(self):
        dhparams = self.session.create_domain_parameters(
            KeyType.DSA, decode_dsa_domain_parameters(DHPARAMS), local=True
        )

        public, private = dhparams.generate_keypair()
        self.assertIsInstance(public, pkcs11.PublicKey)
        self.assertIsInstance(private, pkcs11.PrivateKey)
        # We expect a length of 128 (1024/8) in the vast majority of cases,
        # but since the length of an integer value in DER is not fixed, there's
        # a chance that we end up with a slightly shorter key length.
        # The probability that the length falls short of 120 is vanishingly low, though.
        self.assertGreater(len(public[Attribute.VALUE]), 120)

        data = "Message to sign"
        signature = private.sign(data, mechanism=Mechanism.DSA_SHA1)
        self.assertTrue(public.verify(data, signature, mechanism=Mechanism.DSA_SHA1))

    @requires(Mechanism.DSA_PARAMETER_GEN, Mechanism.DSA_KEY_PAIR_GEN)
    @FIXME.nfast  # returns Function Failed
    def test_generate_keypair_directly(self):
        public, private = self.session.generate_keypair(KeyType.DSA, 1024)
        # See above.
        self.assertGreater(len(public[Attribute.VALUE]), 120)
