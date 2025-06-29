from datetime import datetime
from struct import Struct

from pkcs11.constants import (
    Attribute,
    CertificateType,
    MechanismFlag,
    ObjectClass,
)
from pkcs11.mechanisms import KeyType, Mechanism

# (Pack Function, Unpack Function) functions
_bool = (Struct("?").pack, lambda v: Struct("?").unpack(v)[0])
_ulong = (Struct("L").pack, lambda v: Struct("L").unpack(v)[0])
_str = (lambda s: s.encode("utf-8"), lambda b: b.decode("utf-8"))
_date = (
    lambda s: s.strftime("%Y%m%d").encode("ascii"),
    lambda s: datetime.strptime(s.decode("ascii"), "%Y%m%d").date(),
)
_bytes = (bytes, bytes)
# The PKCS#11 biginteger type is an array of bytes in network byte order.
# If you have an int type, wrap it in biginteger()
_biginteger = _bytes


def _enum(type_):
    """Factory to pack/unpack ints into IntEnums."""
    pack, unpack = _ulong

    return (lambda v: pack(int(v)), lambda v: type_(unpack(v)))


ATTRIBUTE_TYPES = {
    Attribute.ALWAYS_AUTHENTICATE: _bool,
    Attribute.ALWAYS_SENSITIVE: _bool,
    Attribute.APPLICATION: _str,
    Attribute.BASE: _biginteger,
    Attribute.CERTIFICATE_TYPE: _enum(CertificateType),
    Attribute.CHECK_VALUE: _bytes,
    Attribute.CLASS: _enum(ObjectClass),
    Attribute.COEFFICIENT: _biginteger,
    Attribute.DECRYPT: _bool,
    Attribute.DERIVE: _bool,
    Attribute.EC_PARAMS: _bytes,
    Attribute.EC_POINT: _bytes,
    Attribute.ENCRYPT: _bool,
    Attribute.END_DATE: _date,
    Attribute.EXPONENT_1: _biginteger,
    Attribute.EXPONENT_2: _biginteger,
    Attribute.EXTRACTABLE: _bool,
    Attribute.HASH_OF_ISSUER_PUBLIC_KEY: _bytes,
    Attribute.HASH_OF_SUBJECT_PUBLIC_KEY: _bytes,
    Attribute.ID: _bytes,
    Attribute.ISSUER: _bytes,
    Attribute.KEY_GEN_MECHANISM: _enum(Mechanism),
    Attribute.KEY_TYPE: _enum(KeyType),
    Attribute.LABEL: _str,
    Attribute.LOCAL: _bool,
    Attribute.MODIFIABLE: _bool,
    Attribute.COPYABLE: _bool,
    Attribute.MODULUS: _biginteger,
    Attribute.MODULUS_BITS: _ulong,
    Attribute.NEVER_EXTRACTABLE: _bool,
    Attribute.OBJECT_ID: _bytes,
    Attribute.PRIME: _biginteger,
    Attribute.PRIME_BITS: _ulong,
    Attribute.PRIME_1: _biginteger,
    Attribute.PRIME_2: _biginteger,
    Attribute.PRIVATE: _bool,
    Attribute.PRIVATE_EXPONENT: _biginteger,
    Attribute.PUBLIC_EXPONENT: _biginteger,
    Attribute.SENSITIVE: _bool,
    Attribute.SERIAL_NUMBER: _bytes,
    Attribute.SIGN: _bool,
    Attribute.SIGN_RECOVER: _bool,
    Attribute.START_DATE: _date,
    Attribute.SUBJECT: _bytes,
    Attribute.SUBPRIME: _biginteger,
    Attribute.SUBPRIME_BITS: _ulong,
    Attribute.TOKEN: _bool,
    Attribute.TRUSTED: _bool,
    Attribute.UNIQUE_ID: _str,
    Attribute.UNWRAP: _bool,
    Attribute.URL: _str,
    Attribute.VALUE: _biginteger,
    Attribute.VALUE_BITS: _ulong,
    Attribute.VALUE_LEN: _ulong,
    Attribute.VERIFY: _bool,
    Attribute.VERIFY_RECOVER: _bool,
    Attribute.WRAP: _bool,
    Attribute.WRAP_WITH_TRUSTED: _bool,
}
"""
Map of attributes to (serialize, deserialize) functions.
"""


class AttributeMapper:
    """
    Class mapping PKCS#11 attributes to and from Python values.
    """

    def __init__(self):
        self.attribute_types = dict(ATTRIBUTE_TYPES)

    def register_handler(self, key, pack, unpack):
        self.attribute_types[key] = (pack, unpack)

    def pack_attribute(self, key, value):
        """Pack a Attribute value into a bytes array."""
        try:
            pack, _ = self.attribute_types[key]
            return pack(value)
        except KeyError as e:
            raise NotImplementedError(f"Can't pack this {key}.") from e

    def unpack_attributes(self, key, value):
        """Unpack a Attribute bytes array into a Python value."""

        try:
            _, unpack = self.attribute_types[key]
            return unpack(value)
        except KeyError as e:
            raise NotImplementedError(f"Can't unpack this {key}.") from e

    def default_public_key_template(
        self,
        capabilities,
        id,
        label,
        store,
    ):
        # Build attributes
        return {
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.ID: id or b"",
            Attribute.LABEL: label or "",
            Attribute.TOKEN: store,
            # Capabilities
            Attribute.ENCRYPT: MechanismFlag.ENCRYPT & capabilities,
            Attribute.WRAP: MechanismFlag.WRAP & capabilities,
            Attribute.VERIFY: MechanismFlag.VERIFY & capabilities,
        }

    def default_private_key_template(
        self,
        capabilities,
        id,
        label,
        store,
    ):
        return {
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.ID: id or b"",
            Attribute.LABEL: label or "",
            Attribute.TOKEN: store,
            Attribute.PRIVATE: True,
            Attribute.SENSITIVE: True,
            # Capabilities
            Attribute.DECRYPT: MechanismFlag.DECRYPT & capabilities,
            Attribute.UNWRAP: MechanismFlag.UNWRAP & capabilities,
            Attribute.SIGN: MechanismFlag.SIGN & capabilities,
            Attribute.DERIVE: MechanismFlag.DERIVE & capabilities,
        }

    def default_secret_key_template(
        self,
        capabilities,
        id,
        label,
        store,
    ):
        return {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.ID: id or b"",
            Attribute.LABEL: label or "",
            Attribute.TOKEN: store,
            Attribute.PRIVATE: True,
            Attribute.SENSITIVE: True,
            # Capabilities
            Attribute.ENCRYPT: MechanismFlag.ENCRYPT & capabilities,
            Attribute.DECRYPT: MechanismFlag.DECRYPT & capabilities,
            Attribute.WRAP: MechanismFlag.WRAP & capabilities,
            Attribute.UNWRAP: MechanismFlag.UNWRAP & capabilities,
            Attribute.SIGN: MechanismFlag.SIGN & capabilities,
            Attribute.VERIFY: MechanismFlag.VERIFY & capabilities,
            Attribute.DERIVE: MechanismFlag.DERIVE & capabilities,
        }
