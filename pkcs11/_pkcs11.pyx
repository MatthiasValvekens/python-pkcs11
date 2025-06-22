#!python
#cython: language_level=3
"""
High-level Python PKCS#11 Wrapper.

Most class here inherit from pkcs11.types, which provides easier introspection
for Sphinx/Jedi/etc, as this module is not importable without having the
library loaded.
"""

from __future__ import (absolute_import, unicode_literals,
                        print_function, division)

from threading import RLock

from cpython.mem cimport PyMem_Malloc, PyMem_Free

from . import types
from .defaults import *
from .exceptions import *
from .constants import *
from .mechanisms import *
from .types import (
    _CK_UTF8CHAR_to_str,
    _CK_VERSION_to_tuple,
    _CK_MECHANISM_TYPE_to_enum,
    PROTECTED_AUTH,
)


cdef class lib(HasFuncList)

cdef class HasFuncList:
    cdef CK_FUNCTION_LIST *funclist

    def __cinit__(self, *args, **kwargs):
        self.funclist = NULL


cdef assertRV(rv) with gil:
    """Check for an acceptable RV value or thrown an exception."""
    if rv == CKR_OK:
        return
    elif rv == CKR_ATTRIBUTE_TYPE_INVALID:
        exc = AttributeTypeInvalid()
    elif rv == CKR_ATTRIBUTE_VALUE_INVALID:
        exc = AttributeValueInvalid()
    elif rv == CKR_ATTRIBUTE_READ_ONLY:
        exc = AttributeReadOnly()
    elif rv == CKR_ATTRIBUTE_SENSITIVE:
        exc = AttributeSensitive()
    elif rv == CKR_ARGUMENTS_BAD:
        exc = ArgumentsBad()
    elif rv == CKR_BUFFER_TOO_SMALL:
        exc = MemoryError("Buffer was too small. Should never see this.")
    elif rv == CKR_CRYPTOKI_ALREADY_INITIALIZED:
        exc = RuntimeError("Initialisation error (already initialized). Should never see this.")
    elif rv == CKR_CRYPTOKI_NOT_INITIALIZED:
        exc = RuntimeError("Initialisation error (not initialized). Should never see this.")
    elif rv == CKR_DATA_INVALID:
        exc = DataInvalid()
    elif rv == CKR_DATA_LEN_RANGE:
        exc = DataLenRange()
    elif rv == CKR_DOMAIN_PARAMS_INVALID:
        exc = DomainParamsInvalid()
    elif rv == CKR_DEVICE_ERROR:
        exc = DeviceError()
    elif rv == CKR_DEVICE_MEMORY:
        exc = DeviceMemory()
    elif rv == CKR_DEVICE_REMOVED:
        exc = DeviceRemoved()
    elif rv == CKR_ENCRYPTED_DATA_INVALID:
        exc = EncryptedDataInvalid()
    elif rv == CKR_ENCRYPTED_DATA_LEN_RANGE:
        exc = EncryptedDataLenRange()
    elif rv == CKR_EXCEEDED_MAX_ITERATIONS:
        exc = ExceededMaxIterations()
    elif rv == CKR_FUNCTION_CANCELED:
        exc = FunctionCancelled()
    elif rv == CKR_FUNCTION_FAILED:
        exc = FunctionFailed()
    elif rv == CKR_FUNCTION_REJECTED:
        exc = FunctionRejected()
    elif rv == CKR_FUNCTION_NOT_SUPPORTED:
        exc = FunctionNotSupported()
    elif rv == CKR_KEY_HANDLE_INVALID:
        exc = KeyHandleInvalid()
    elif rv == CKR_KEY_INDIGESTIBLE:
        exc = KeyIndigestible()
    elif rv == CKR_KEY_NEEDED:
        exc = KeyNeeded()
    elif rv == CKR_KEY_NOT_NEEDED:
        exc = KeyNotNeeded()
    elif rv == CKR_KEY_SIZE_RANGE:
        exc = KeySizeRange()
    elif rv == CKR_KEY_NOT_WRAPPABLE:
        exc = KeyNotWrappable()
    elif rv == CKR_KEY_TYPE_INCONSISTENT:
        exc = KeyTypeInconsistent()
    elif rv == CKR_KEY_UNEXTRACTABLE:
        exc = KeyUnextractable()
    elif rv == CKR_GENERAL_ERROR:
        exc = GeneralError()
    elif rv == CKR_HOST_MEMORY:
        exc = HostMemory()
    elif rv == CKR_MECHANISM_INVALID:
        exc = MechanismInvalid()
    elif rv == CKR_MECHANISM_PARAM_INVALID:
        exc = MechanismParamInvalid()
    elif rv == CKR_NO_EVENT:
        exc = NoEvent()
    elif rv == CKR_OBJECT_HANDLE_INVALID:
        exc = ObjectHandleInvalid()
    elif rv == CKR_OPERATION_ACTIVE:
        exc = OperationActive()
    elif rv == CKR_OPERATION_NOT_INITIALIZED:
        exc = OperationNotInitialized()
    elif rv == CKR_PIN_EXPIRED:
        exc = PinExpired()
    elif rv == CKR_PIN_INCORRECT:
        exc = PinIncorrect()
    elif rv == CKR_PIN_INVALID:
        exc = PinInvalid()
    elif rv == CKR_PIN_LOCKED:
        exc = PinLocked()
    elif rv == CKR_PIN_TOO_WEAK:
        exc = PinTooWeak()
    elif rv == CKR_PUBLIC_KEY_INVALID:
        exc = PublicKeyInvalid()
    elif rv == CKR_RANDOM_NO_RNG:
        exc = RandomNoRNG()
    elif rv == CKR_RANDOM_SEED_NOT_SUPPORTED:
        exc = RandomSeedNotSupported()
    elif rv == CKR_SESSION_CLOSED:
        exc = SessionClosed()
    elif rv == CKR_SESSION_COUNT:
        exc = SessionCount()
    elif rv == CKR_SESSION_EXISTS:
        exc = SessionExists()
    elif rv == CKR_SESSION_HANDLE_INVALID:
        exc = SessionHandleInvalid()
    elif rv == CKR_SESSION_PARALLEL_NOT_SUPPORTED:
        exc = RuntimeError("Parallel not supported. Should never see this.")
    elif rv == CKR_SESSION_READ_ONLY:
        exc = SessionReadOnly()
    elif rv == CKR_SESSION_READ_ONLY_EXISTS:
        exc = SessionReadOnlyExists()
    elif rv == CKR_SESSION_READ_WRITE_SO_EXISTS:
        exc = SessionReadWriteSOExists()
    elif rv == CKR_SIGNATURE_LEN_RANGE:
        exc = SignatureLenRange()
    elif rv == CKR_SIGNATURE_INVALID:
        exc = SignatureInvalid()
    elif rv == CKR_TEMPLATE_INCOMPLETE:
        exc = TemplateIncomplete()
    elif rv == CKR_TEMPLATE_INCONSISTENT:
        exc = TemplateInconsistent()
    elif rv == CKR_SLOT_ID_INVALID:
        exc = SlotIDInvalid()
    elif rv == CKR_TOKEN_NOT_PRESENT:
        exc = TokenNotPresent()
    elif rv == CKR_TOKEN_NOT_RECOGNIZED:
        exc = TokenNotRecognised()
    elif rv == CKR_TOKEN_WRITE_PROTECTED:
        exc = TokenWriteProtected()
    elif rv == CKR_UNWRAPPING_KEY_HANDLE_INVALID:
        exc = UnwrappingKeyHandleInvalid()
    elif rv == CKR_UNWRAPPING_KEY_SIZE_RANGE:
        exc = UnwrappingKeySizeRange()
    elif rv == CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
        exc = UnwrappingKeyTypeInconsistent()
    elif rv == CKR_USER_NOT_LOGGED_IN:
        exc = UserNotLoggedIn()
    elif rv == CKR_USER_ALREADY_LOGGED_IN:
        exc = UserAlreadyLoggedIn()
    elif rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
        exc = AnotherUserAlreadyLoggedIn()
    elif rv == CKR_USER_PIN_NOT_INITIALIZED:
        exc = UserPinNotInitialized()
    elif rv == CKR_USER_TOO_MANY_TYPES:
        exc = UserTooManyTypes()
    elif rv == CKR_USER_TYPE_INVALID:
        exc = RuntimeError("User type invalid. Should never see this.")
    elif rv == CKR_WRAPPED_KEY_INVALID:
        exc = WrappedKeyInvalid()
    elif rv == CKR_WRAPPED_KEY_LEN_RANGE:
        exc = WrappedKeyLenRange()
    elif rv == CKR_WRAPPING_KEY_HANDLE_INVALID:
        exc = WrappingKeyHandleInvalid()
    elif rv == CKR_WRAPPING_KEY_SIZE_RANGE:
        exc = WrappingKeySizeRange()
    elif rv == CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
        exc = WrappingKeyTypeInconsistent()
    else:
        exc = PKCS11Error("Unmapped error code %s" % hex(rv))
    raise exc



cdef class AttributeList:
    """
    A list of CK_ATTRIBUTE objects.
    """

    cdef CK_ATTRIBUTE *data
    """CK_ATTRIBUTE * representation of the data."""
    cdef CK_ULONG count
    """Length of `data`."""

    cdef _values

    def __cinit__(self, attrs):
        attrs = dict(attrs)
        self.count = count = <CK_ULONG> len(attrs)

        self.data = <CK_ATTRIBUTE *> PyMem_Malloc(count * sizeof(CK_ATTRIBUTE))
        if not self.data:
            raise MemoryError()

        # Turn the values into bytes and store them so we have pointers
        # to them.
        self._values = [
            (key, _pack_attribute(key, value))
            for key, value in attrs.items()
        ]

        for index, (key, value) in enumerate(self._values):
            self.data[index].type = key
            self.data[index].pValue = <CK_CHAR *> value
            self.data[index].ulValueLen = <CK_ULONG>len(value)

    def __dealloc__(self):
        PyMem_Free(self.data)


cdef class MechanismWithParam:
    """
    Python wrapper for a Mechanism with its parameter
    """

    cdef CK_MECHANISM *data
    """The mechanism."""
    cdef void *param
    """Reference to a pointer we might need to free."""

    def __cinit__(self, *args):
        self.data = <CK_MECHANISM *> PyMem_Malloc(sizeof(CK_MECHANISM))
        self.param = NULL

    def __init__(self, key_type, mapping, mechanism=None, param=None):
        if mechanism is None:
            try:
                mechanism = mapping[key_type]
            except KeyError:
                raise ArgumentsBad("No default mechanism for this key type. "
                                    "Please specify `mechanism`.")

        if not isinstance(mechanism, Mechanism):
            raise ArgumentsBad("`mechanism` must be a Mechanism.")
        # Possible types of parameters we might need to allocate
        # These are used to make assigning to the object we malloc() easier
        # FIXME: is there a better way to do this?
        cdef CK_RSA_PKCS_OAEP_PARAMS *oaep_params
        cdef CK_RSA_PKCS_PSS_PARAMS *pss_params
        cdef CK_EDDSA_PARAMS *eddsa_params
        cdef CK_ECDH1_DERIVE_PARAMS *ecdh1_params
        cdef CK_KEY_DERIVATION_STRING_DATA *aes_ecb_params
        cdef CK_AES_CBC_ENCRYPT_DATA_PARAMS *aes_cbc_params

        # Unpack mechanism parameters

        if mechanism == Mechanism.AES_ECB_ENCRYPT_DATA:
            paramlen = sizeof(CK_KEY_DERIVATION_STRING_DATA)
            self.param = aes_ecb_params = \
                <CK_KEY_DERIVATION_STRING_DATA *> PyMem_Malloc(paramlen)
            aes_ecb_params.pData = <CK_BYTE *> param
            aes_ecb_params.ulLen = <CK_ULONG> len(param)

        elif isinstance(param, bytes):
            # Note: this is an escape hatch of sorts that can be used to provide parameters for
            #  unsupported algorithms in raw binary form.
            # We include it at this point in the chain for forwards compatibility reasons:
            #  if at a later point, "first class" support for the unsupported mechanism is added
            #  to the library, existing code that used this "raw mode" workaround will keep working
            #  because this branch takes priority.
            #
            # The parameter convention for AES_ECB_ENCRYPT_DATA predates this ordering decision,
            #  so it takes precedence over this branch for backwards compatibility.
            self.data.pParameter = <CK_BYTE *> param
            paramlen =  len(param)

        elif mechanism == Mechanism.RSA_PKCS_OAEP:
            paramlen = sizeof(CK_RSA_PKCS_OAEP_PARAMS)
            self.param = oaep_params = \
                <CK_RSA_PKCS_OAEP_PARAMS *> PyMem_Malloc(paramlen)

            oaep_params.source = CKZ_DATA_SPECIFIED

            if param is None:
                param = DEFAULT_MECHANISM_PARAMS[mechanism]

            (oaep_params.hashAlg, oaep_params.mgf, source_data) = param

            if source_data is None:
                oaep_params.pSourceData = NULL
                oaep_params.ulSourceDataLen = <CK_ULONG> 0
            else:
                oaep_params.pSourceData = <CK_BYTE *> source_data
                oaep_params.ulSourceDataLen = <CK_ULONG> len(source_data)

        elif mechanism in (Mechanism.RSA_PKCS_PSS,
                           Mechanism.SHA1_RSA_PKCS_PSS,
                           Mechanism.SHA224_RSA_PKCS_PSS,
                           Mechanism.SHA256_RSA_PKCS_PSS,
                           Mechanism.SHA384_RSA_PKCS_PSS,
                           Mechanism.SHA512_RSA_PKCS_PSS):
            paramlen = sizeof(CK_RSA_PKCS_PSS_PARAMS)
            self.param = pss_params = \
                <CK_RSA_PKCS_PSS_PARAMS *> PyMem_Malloc(paramlen)

            if param is None:
                # All PSS mechanisms have the same defaults
                param = DEFAULT_MECHANISM_PARAMS[Mechanism.RSA_PKCS_PSS]

            (pss_params.hashAlg, pss_params.mgf, pss_params.sLen) = param

        elif mechanism == Mechanism.EDDSA and param is not None:
            paramlen = sizeof(CK_EDDSA_PARAMS)
            self.param = eddsa_params = \
                <CK_EDDSA_PARAMS *> PyMem_Malloc(paramlen)
            (eddsa_params.phFlag, context_data) = param
            if context_data is None:
                eddsa_params.pContextData = NULL
                eddsa_params.ulContextDataLen = 0
            else:
                eddsa_params.pContextData = context_data
                eddsa_params.ulContextDataLen = <CK_ULONG> len(context_data)

        elif mechanism in (
                Mechanism.ECDH1_DERIVE,
                Mechanism.ECDH1_COFACTOR_DERIVE):
            paramlen = sizeof(CK_ECDH1_DERIVE_PARAMS)
            self.param = ecdh1_params = \
                <CK_ECDH1_DERIVE_PARAMS *> PyMem_Malloc(paramlen)

            (ecdh1_params.kdf, shared_data, public_data) = param

            if shared_data is None:
                ecdh1_params.pSharedData = NULL
                ecdh1_params.ulSharedDataLen = 0
            else:
                ecdh1_params.pSharedData = shared_data
                ecdh1_params.ulSharedDataLen = <CK_ULONG> len(shared_data)

            ecdh1_params.pPublicData = public_data
            ecdh1_params.ulPublicDataLen = <CK_ULONG> len(public_data)

        elif mechanism == Mechanism.AES_CBC_ENCRYPT_DATA:
            paramlen = sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS)
            self.param = aes_cbc_params = \
                    <CK_AES_CBC_ENCRYPT_DATA_PARAMS *> PyMem_Malloc(paramlen)
            (iv, data) = param
            aes_cbc_params.iv = iv[:16]
            aes_cbc_params.pData = <CK_BYTE *> data
            aes_cbc_params.length = <CK_ULONG> len(data)

        elif param is None:
            self.data.pParameter = NULL
            paramlen = 0

        else:
            raise ArgumentsBad("Unexpected argument to mechanism_param")

        self.data.mechanism = mechanism
        self.data.ulParameterLen = <CK_ULONG> paramlen

        if self.param != NULL:
            self.data.pParameter = self.param

    def __dealloc__(self):
        PyMem_Free(self.data)
        PyMem_Free(self.param)


cdef class Slot(HasFuncList, types.Slot):
    """Extend Slot with implementation."""

    cdef readonly CK_SLOT_ID slot_id
    """Slot identifier (opaque)."""
    cdef readonly str slot_description
    """Slot name (:class:`str`)."""
    cdef readonly str manufacturer_id
    """Slot/device manufacturer's name (:class:`str`)."""
    cdef CK_FLAGS slot_flags
    cdef CK_VERSION hw_version
    cdef CK_VERSION fw_version

    @staticmethod
    cdef Slot make(CK_FUNCTION_LIST *funclist, CK_SLOT_ID slot_id, CK_SLOT_INFO info):
        description = info.slotDescription[:sizeof(info.slotDescription)]
        manufacturer_id = info.manufacturerID[:sizeof(info.manufacturerID)]

        cdef Slot slot = Slot.__new__(Slot)
        slot.funclist = funclist

        slot.slot_id = slot_id
        slot.slot_description = _CK_UTF8CHAR_to_str(description)
        slot.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturer_id)
        slot.hw_version = info.hardwareVersion
        slot.fw_version = info.firmwareVersion
        slot.slot_flags = info.flags
        return slot

    def __init__(self):
        raise TypeError

    @property
    def flags(self):
        """Capabilities of this slot (:class:`SlotFlag`)."""
        return SlotFlag(self.slot_flags)

    @property
    def hardware_version(self):
        """Hardware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self.hw_version)

    @property
    def firmware_version(self):
        """Firmware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self.fw_version)

    def get_token(self):
        cdef CK_SLOT_ID slot_id = self.slot_id
        cdef CK_TOKEN_INFO info
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetTokenInfo(slot_id, &info)
        assertRV(retval)

        return Token.make(self, info)

    def get_mechanisms(self):
        cdef CK_SLOT_ID slot_id = self.slot_id
        cdef CK_ULONG count
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetMechanismList(slot_id, NULL, &count)
        assertRV(retval)

        if count == 0:
            return set()

        cdef CK_MECHANISM_TYPE [:] mechanisms = CK_ULONG_buffer(count)

        with nogil:
            retval = self.funclist.C_GetMechanismList(slot_id, &mechanisms[0], &count)
        assertRV(retval)

        return set(map(_CK_MECHANISM_TYPE_to_enum, mechanisms))

    def get_mechanism_info(self, mechanism):
        cdef CK_SLOT_ID slot_id = self.slot_id
        cdef CK_MECHANISM_TYPE mech_type = mechanism
        cdef CK_MECHANISM_INFO info
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetMechanismInfo(slot_id, mech_type, &info)
        assertRV(retval)

        return types.MechanismInfo(self, mechanism, **info)

    def _identity(self):
        return Slot.__name__, self.slot_id

    def __str__(self):
        return "\n".join(
            (
                "Slot Description: %s" % self.slot_description,
                "Manufacturer ID: %s" % self.manufacturer_id,
                "Hardware Version: %s.%s" % self.hardware_version,
                "Firmware Version: %s.%s" % self.firmware_version,
                "Flags: %s" % self.flags,
            )
        )

    def __repr__(self):
        return "<{klass} (slotID={slot_id} flags={flags})>".format(
            klass=type(self).__name__, slot_id=self.slot_id, flags=str(self.flags)
        )


cdef class Token(HasFuncList, types.Token):
    """Extend Token with implementation."""

    cdef readonly Slot slot
    """The :class:`Slot` this token is installed in."""
    cdef readonly str label
    """Label of this token (:class:`str`)."""
    cdef readonly bytes serial
    """Serial number of this token (:class:`bytes`)."""
    cdef readonly str manufacturer_id
    """Manufacturer ID."""
    cdef readonly str model
    """Model name."""
    cdef CK_FLAGS token_flags
    cdef CK_VERSION hw_version
    cdef CK_VERSION fw_version

    @staticmethod
    cdef Token make(Slot slot, CK_TOKEN_INFO info):
        label = info.label[:sizeof(info.label)]
        serial_number = info.serialNumber[:sizeof(info.serialNumber)]
        model = info.model[:sizeof(info.model)]
        manufacturer_id = info.manufacturerID[:sizeof(info.manufacturerID)]

        cdef Token token = Token.__new__(Token)
        token.funclist = slot.funclist
        token.slot = slot
        token.label = _CK_UTF8CHAR_to_str(label)
        token.serial = serial_number.rstrip()
        token.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturer_id)
        token.model = _CK_UTF8CHAR_to_str(model)
        token.hw_version = info.hardwareVersion
        token.fw_version = info.firmwareVersion
        token.token_flags = info.flags
        return token

    def __init__(self):
        raise TypeError

    @property
    def flags(self):
        """Capabilities of this token (:class:`TokenFlag`)."""
        return TokenFlag(self.token_flags)

    @property
    def hardware_version(self):
        """Hardware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self.hw_version)

    @property
    def firmware_version(self):
        """Firmware version (:class:`tuple`)."""
        return _CK_VERSION_to_tuple(self.fw_version)

    def open(self, rw=False, user_pin=None, so_pin=None, user_type=None):
        cdef CK_SLOT_ID slot_id = self.slot.slot_id
        cdef CK_SESSION_HANDLE handle
        cdef CK_FLAGS flags = CKF_SERIAL_SESSION
        cdef CK_USER_TYPE final_user_type
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length
        cdef CK_RV retval
        cdef CK_USER_TYPE c_user_type

        if rw:
            flags |= CKF_RW_SESSION

        if user_pin is not None and so_pin is not None:
            raise ArgumentsBad("Set either `user_pin` or `so_pin`")
        elif user_pin is PROTECTED_AUTH:
            pin = None
            c_user_type = user_type if user_type is not None else CKU_USER
        elif so_pin is PROTECTED_AUTH:
            pin = None
            c_user_type = CKU_SO
        elif user_pin is not None:
            pin = user_pin.encode('utf-8')
            c_user_type = user_type if user_type is not None else CKU_USER
        elif so_pin is not None:
            pin = so_pin.encode('utf-8')
            c_user_type = CKU_SO
        else:
            pin = None
            c_user_type = CKU_USER_NOBODY

        with nogil:
            retval = self.funclist.C_OpenSession(slot_id, flags, NULL, NULL, &handle)
        assertRV(retval)

        if so_pin is PROTECTED_AUTH or user_pin is PROTECTED_AUTH:
            if self.flags & TokenFlag.PROTECTED_AUTHENTICATION_PATH:
                with nogil:
                    retval = self.funclist.C_Login(handle, c_user_type, NULL, 0)
                assertRV(retval)
            else:
                raise ArgumentsBad("Protected authentication is not supported by loaded module")
        elif pin is not None:
            pin_data = pin
            pin_length = <CK_ULONG> len(pin)

            with nogil:
                retval = self.funclist.C_Login(handle, c_user_type, pin_data, pin_length)
            assertRV(retval)

        return Session.make(self, handle, rw=<bint> rw, user_type=c_user_type)

    def __str__(self):
        return self.label

    def _identity(self):
        return Token.__name__, self.slot

    def __repr__(self):
        return "<{klass} (label='{label}' serial={serial} flags={flags})>".format(
            klass=type(self).__name__, label=self.label, serial=self.serial, flags=str(self.flags)
        )


cdef class SearchIter:
    """Iterate a search for objects on a session."""

    cdef Session session
    cdef bint active

    def __cinit__(self, session, attrs):
        self.session = session
        self.active = False

    def __init__(self, session, attrs):
        cdef AttributeList template = AttributeList(attrs)
        self.start_search(template)

    def __iter__(self):
        return self

    def __next__(self):
        """Get the next object."""
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj
        cdef CK_ULONG count
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_FindObjects(handle, &obj, 1, &count)
        assertRV(retval)

        if count == 0:
            self._finalize()
            raise StopIteration()
        else:
            return make_object(self.session, obj)

    def __del__(self):
        """Close the search."""
        self._finalize()

    def __enter__(self):
        # it would make sense to start the search here, but we can't do that for
        # API compatibility reasons
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._finalize()

    cdef start_search(self, AttributeList template):
        self.session.operation_lock.acquire()
        self.active = True

        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_ATTRIBUTE *attr_data = template.data
        cdef CK_ULONG attr_count = template.count
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_FindObjectsInit(handle, attr_data, attr_count)
        assertRV(retval)

    def _finalize(self):
        """Finish the operation."""
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_RV retval

        if self.active:
            self.active = False

            with nogil:
                retval = self.session.funclist.C_FindObjectsFinal(handle)
            assertRV(retval)

            self.session.operation_lock.release()


def merge_templates(default_template, *user_templates):
    template = default_template.copy()

    for user_template in user_templates:
        if user_template is not None:
            template.update(user_template)

    return {
        key: value
        for key, value in template.items()
        if value is not DEFAULT
    }


cdef class Session(HasFuncList, types.Session):
    """Extend Session with implementation."""

    # FIXME this shouldn't have to be public once we're done here
    cdef CK_SESSION_HANDLE handle
    cdef readonly Token token
    """:class:`Token` this session is on."""
    cdef readonly bint rw
    """True if this is a read/write session."""
    cdef CK_USER_TYPE _user_type
    cdef object operation_lock

    @staticmethod
    cdef Session make(Token token, CK_SESSION_HANDLE handle, bint rw, CK_USER_TYPE user_type):
        cdef Session session = Session.__new__(Session)

        session.funclist = token.funclist
        session.token = token

        session.handle = handle
        # Big operation lock prevents other threads from entering/reentering
        # operations. If the same thread enters the lock, they will get a
        # Cryptoki warning
        session.operation_lock = RLock()

        session.rw = rw
        session._user_type = user_type
        return session

    def __init__(self):
        raise TypeError

    def _identity(self):
        return Session.__name__, self.token, self.handle

    @property
    def user_type(self):
        """User type for this session (:class:`pkcs11.constants.UserType`)."""
        return UserType(self._user_type)

    def close(self):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_RV retval

        if self.user_type != UserType.NOBODY:
            with nogil:
                retval = self.funclist.C_Logout(handle)
            assertRV(retval)

        with nogil:
            retval = self.funclist.C_CloseSession(handle)
        assertRV(retval)

    def get_objects(self, attrs=None):
        return SearchIter(self, attrs or {})

    def create_object(self, attrs):
        template = AttributeList(attrs)

        cdef CK_OBJECT_HANDLE handle = self.handle
        cdef CK_ATTRIBUTE *attr_data = template.data
        cdef CK_ULONG attr_count = template.count
        cdef CK_OBJECT_HANDLE new
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_CreateObject(handle, attr_data, attr_count, &new)
        assertRV(retval)

        return make_object(self, new)

    def create_domain_parameters(self, key_type, attrs,
                                 local=False, store=False):
        if local and store:
            raise ArgumentsBad("Cannot set both `local` and `store`")

        attrs = dict(attrs)
        attrs[Attribute.CLASS] = ObjectClass.DOMAIN_PARAMETERS
        attrs[Attribute.KEY_TYPE] = key_type
        attrs[Attribute.TOKEN] = store

        if local:
            return LocalDomainParameters(self, attrs)
        else:
            return self.create_object(attrs)

    def generate_domain_parameters(self, key_type, param_length, store=False,
                                   mechanism=None, mechanism_param=None,
                                   template=None):
        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if not isinstance(param_length, int):
            raise ArgumentsBad("`param_length` is the length in bits.")

        mech = MechanismWithParam(
            key_type, DEFAULT_PARAM_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        template_ = {
            Attribute.CLASS: ObjectClass.DOMAIN_PARAMETERS,
            Attribute.TOKEN: store,
            Attribute.PRIME_BITS: param_length,
        }
        attrs = AttributeList(merge_templates(template_, template))

        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE obj
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GenerateKey(handle, mech_data, attr_data, attr_count, &obj)
        assertRV(retval)

        return make_object(self, obj)

    def generate_key(self, key_type, key_length=None,
                     id=None, label=None,
                     store=False, capabilities=None,
                     mechanism=None, mechanism_param=None,
                     template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if key_length is not None and not isinstance(key_length, int):
            raise ArgumentsBad("`key_length` is the length in bits.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(
            key_type, DEFAULT_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        # Build attributes
        template_ = {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.ID: id or b'',
            Attribute.LABEL: label or '',
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

        if key_type not in (KeyType.DES2, KeyType.DES3, KeyType.GOST28147, KeyType.SEED):
            if key_length is None:
                raise ArgumentsBad("Must provide `key_length'")

            template_[Attribute.VALUE_LEN] = key_length // 8  # In bytes

        attrs = AttributeList(merge_templates(template_, template))

        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key

        with nogil:
            retval = self.funclist.C_GenerateKey(handle, mech_data, attr_data, attr_count, &key)
        assertRV(retval)

        return make_object(self, key)

    def _generate_keypair(self, key_type, key_length=None,
                          id=None, label=None,
                          store=False, capabilities=None,
                          mechanism=None, mechanism_param=None,
                          public_template=None, private_template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if key_length is not None and not isinstance(key_length, int):
            raise ArgumentsBad("`key_length` is the length in bits.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(
            key_type, DEFAULT_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        # Build attributes
        public_template_ = {
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.ID: id or b'',
            Attribute.LABEL: label or '',
            Attribute.TOKEN: store,
            # Capabilities
            Attribute.ENCRYPT: MechanismFlag.ENCRYPT & capabilities,
            Attribute.WRAP: MechanismFlag.WRAP & capabilities,
            Attribute.VERIFY: MechanismFlag.VERIFY & capabilities,
        }

        if key_type is KeyType.RSA:
            if key_length is None:
                raise ArgumentsBad("Must provide `key_length'")

            # Some PKCS#11 implementations don't default this, it makes sense
            # to do it here
            public_template_.update({
                Attribute.PUBLIC_EXPONENT: b'\1\0\1',
                Attribute.MODULUS_BITS: key_length,
            })

        public_attrs = AttributeList(merge_templates(public_template_, public_template))

        private_template_ = {
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.ID: id or b'',
            Attribute.LABEL: label or '',
            Attribute.TOKEN: store,
            Attribute.PRIVATE: True,
            Attribute.SENSITIVE: True,
            # Capabilities
            Attribute.DECRYPT: MechanismFlag.DECRYPT & capabilities,
            Attribute.UNWRAP: MechanismFlag.UNWRAP & capabilities,
            Attribute.SIGN: MechanismFlag.SIGN & capabilities,
            Attribute.DERIVE: MechanismFlag.DERIVE & capabilities,
        }
        private_attrs = AttributeList(merge_templates(private_template_, private_template))

        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_ATTRIBUTE *public_attr_data = public_attrs.data
        cdef CK_ULONG public_attr_count = public_attrs.count
        cdef CK_ATTRIBUTE *private_attr_data = private_attrs.data
        cdef CK_ULONG private_attr_count = private_attrs.count
        cdef CK_OBJECT_HANDLE public_key
        cdef CK_OBJECT_HANDLE private_key
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GenerateKeyPair(handle, mech_data, public_attr_data, public_attr_count, private_attr_data, private_attr_count, &public_key, &private_key)
        assertRV(retval)

        return (make_object(self, public_key),
                make_object(self, private_key))

    def seed_random(self, seed):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_BYTE *seed_data = seed
        cdef CK_ULONG seed_len = <CK_ULONG> len(seed)
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_SeedRandom(handle, seed_data, seed_len)
        assertRV(retval)

    def generate_random(self, nbits):
        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_ULONG length = nbits // 8
        cdef CK_CHAR [:] random = CK_BYTE_buffer(length)
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GenerateRandom(handle, &random[0], length)
        assertRV(retval)

        return bytes(random)

    def _digest(self, data, mechanism=None, mechanism_param=None):
        mech = MechanismWithParam(None, {}, mechanism, mechanism_param)

        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef CK_BYTE [:] digest
        cdef CK_ULONG length
        cdef CK_RV retval

        with self.operation_lock:
            with nogil:
                retval = self.funclist.C_DigestInit(handle, mech_data)
            assertRV(retval)

            with nogil:
                # Run once to get the length
                retval = self.funclist.C_Digest(handle, data_ptr, data_len, NULL, &length)
            assertRV(retval)

            digest = CK_BYTE_buffer(length)

            with nogil:
                retval = self.funclist.C_Digest(handle, data_ptr, data_len, &digest[0], &length)
            assertRV(retval)

            return bytes(digest[:length])

    def _digest_generator(self, data, mechanism=None, mechanism_param=None):
        mech = MechanismWithParam(None, {}, mechanism, mechanism_param)

        cdef CK_SESSION_HANDLE handle = self.handle
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE key
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len
        cdef CK_BYTE [:] digest
        cdef CK_ULONG length
        cdef CK_RV retval

        with self.operation_lock:
            with nogil:
                retval = self.funclist.C_DigestInit(handle, mech_data)
            assertRV(retval)

            for block in data:
                if isinstance(block, types.Key):
                    key = block.handle

                    with nogil:
                        retval = self.funclist.C_DigestKey(handle, key)
                    assertRV(retval)
                else:
                    data_ptr = block
                    data_len = <CK_ULONG> len(block)

                    with nogil:
                        retval = self.funclist.C_DigestUpdate(handle, data_ptr, data_len)
                    assertRV(retval)

            # Run once to get the length
            with nogil:
                retval = self.funclist.C_DigestFinal(handle, NULL, &length)
            assertRV(retval)

            digest = CK_BYTE_buffer(length)

            with nogil:
                retval = self.funclist.C_DigestFinal(handle, &digest[0], &length)
            assertRV(retval)

            return bytes(digest[:length])


cdef class ObjectHandleWrapper(HasFuncList):
    """
    Class implementing generic operations on PKCS#11 objects.
    """

    cdef readonly Session session
    cdef readonly CK_OBJECT_HANDLE handle

    @staticmethod
    cdef ObjectHandleWrapper wrap(Session session, CK_OBJECT_HANDLE handle):
        cdef ObjectHandleWrapper obj = ObjectHandleWrapper.__new__(ObjectHandleWrapper)
        obj.funclist = session.funclist
        obj.session = session
        obj.handle = handle
        return obj

    def __init__(self):
        raise TypeError

    def __getitem__(self, key):
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ATTRIBUTE template
        cdef CK_RV retval

        template.type = key
        template.pValue = NULL
        template.ulValueLen = <CK_ULONG> 0

        # Find out the attribute size
        with nogil:
            retval = self.funclist.C_GetAttributeValue(handle, obj, &template, 1)
        if retval == CK_UNAVAILABLE_INFORMATION:
            return None
        assertRV(retval)

        if template.ulValueLen == 0:
            return _unpack_attributes(key, b'')

        # Put a buffer of the right length in place
        cdef CK_CHAR [:] value = CK_BYTE_buffer(template.ulValueLen)
        template.pValue = <CK_CHAR *> &value[0]

        # Request the value
        with nogil:
            retval = self.funclist.C_GetAttributeValue(handle, obj, &template, 1)
        if retval == CK_UNAVAILABLE_INFORMATION:
            return None
        assertRV(retval)

        return _unpack_attributes(key, value)

    def __setitem__(self, key, value):
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ATTRIBUTE template
        cdef CK_RV retval

        value = _pack_attribute(key, value)

        template.type = key
        template.pValue = <CK_CHAR *> value
        template.ulValueLen = <CK_ULONG>len(value)

        with nogil:
            retval = self.funclist.C_SetAttributeValue(handle, obj, &template, 1)
        assertRV(retval)

    def destroy(self):
        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_DestroyObject(handle, obj)
        assertRV(retval)

    def copy(self, attrs):
        template = AttributeList(attrs)

        cdef CK_SESSION_HANDLE handle = self.session.handle
        cdef CK_OBJECT_HANDLE obj = self.handle
        cdef CK_ATTRIBUTE *attr_data = template.data
        cdef CK_ULONG attr_count = template.count
        cdef CK_OBJECT_HANDLE new_obj
        cdef CK_RV retval

        with nogil:
            retval = self.session.funclist.C_CopyObject(handle, obj, attr_data, attr_count, &new_obj)
        assertRV(retval)
        return new_obj

    def identity(self):
        return ObjectHandleWrapper.__name__, self.session, self.handle

class Object(types.Object):
    """Expand Object with an implementation."""

    def __init__(self, wrapper: ObjectHandleWrapper):
        self.wrapper = wrapper

    def __getitem__(self, item):
        return self.wrapper[item]

    def __setitem__(self, key, value):
        self.wrapper[key] = value

    @property
    def session(self):
        return self.wrapper.session

    @property
    def handle(self):
        return self.wrapper.handle

    def copy(self, attrs):
        new_obj = self.wrapper.copy(attrs)
        return make_object(self.wrapper.session, new_obj)

    def destroy(self):
        self.wrapper.destroy()

    def _identity(self):
        return Object.__name__, self.wrapper.identity()


cdef object make_object(Session session, CK_OBJECT_HANDLE handle) with gil:
    """
    Make an object with the right bases for its class and capabilities.
    """
    wrapper = ObjectHandleWrapper.wrap(session, handle)

    try:
        # Determine a list of base classes to manufacture our class with
        # FIXME: we should really request all of these attributes in
        # one go
        object_class = wrapper[Attribute.CLASS]
        bases = (_CLASS_MAP[object_class],)

        # Build a list of mixins for this new class
        for attribute, mixin in (
                (Attribute.ENCRYPT, EncryptMixin),
                (Attribute.DECRYPT, DecryptMixin),
                (Attribute.SIGN, SignMixin),
                (Attribute.VERIFY, VerifyMixin),
                (Attribute.WRAP, WrapMixin),
                (Attribute.UNWRAP, UnwrapMixin),
                (Attribute.DERIVE, DeriveMixin),
        ):
            try:
                if wrapper[attribute]:
                    bases += (mixin,)
            # nFast returns FunctionFailed when you request an attribute
            # it doesn't like.
            except (AttributeTypeInvalid, FunctionFailed):
                pass

        bases += (Object,)

        # Manufacture a class with the right capabilities.
        klass = type(bases[0].__name__, bases, {})

        return klass(wrapper)

    except KeyError:
        return Object(wrapper)


class SecretKey(types.SecretKey):
    pass


class PublicKey(types.PublicKey):
    pass


class PrivateKey(types.PrivateKey):
    pass


class GenerateWithParametersMixin(types.DomainParameters):
    def generate_keypair(self,
                         id=None, label=None,
                         store=False, capabilities=None,
                         mechanism=None, mechanism_param=None,
                         public_template=None, private_template=None):

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[self.key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(
            self.key_type, DEFAULT_GENERATE_MECHANISMS,
            mechanism, mechanism_param)

        # Build attributes
        public_template_ = {
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.ID: id or b'',
            Attribute.LABEL: label or '',
            Attribute.TOKEN: store,
            # Capabilities
            Attribute.ENCRYPT: MechanismFlag.ENCRYPT & capabilities,
            Attribute.WRAP: MechanismFlag.WRAP & capabilities,
            Attribute.VERIFY: MechanismFlag.VERIFY & capabilities,
        }

        # Copy in our domain parameters.
        # Not all parameters are appropriate for all domains.
        for attribute in (
                Attribute.BASE,
                Attribute.PRIME,
                Attribute.SUBPRIME,
                Attribute.EC_PARAMS,
        ):
            try:
                public_template_[attribute] = self[attribute]
                # nFast returns FunctionFailed for parameters it doesn't like
            except (AttributeTypeInvalid, FunctionFailed):
                pass

        public_attrs = AttributeList(merge_templates(public_template_, public_template))

        private_template_ = {
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.ID: id or b'',
            Attribute.LABEL: label or '',
            Attribute.TOKEN: store,
            Attribute.PRIVATE: True,
            Attribute.SENSITIVE: True,
            # Capabilities
            Attribute.DECRYPT: MechanismFlag.DECRYPT & capabilities,
            Attribute.UNWRAP: MechanismFlag.UNWRAP & capabilities,
            Attribute.SIGN: MechanismFlag.SIGN & capabilities,
            Attribute.DERIVE: MechanismFlag.DERIVE & capabilities,
        }
        private_attrs = AttributeList(merge_templates(private_template_, private_template))

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_ATTRIBUTE *public_attr_data = public_attrs.data
        cdef CK_ULONG public_attr_count = public_attrs.count
        cdef CK_ATTRIBUTE *private_attr_data = private_attrs.data
        cdef CK_ULONG private_attr_count = private_attrs.count
        cdef CK_OBJECT_HANDLE public_key
        cdef CK_OBJECT_HANDLE private_key
        cdef CK_RV retval

        with nogil:
            retval = session.funclist.C_GenerateKeyPair(session.handle, mech_data, public_attr_data, public_attr_count, private_attr_data, private_attr_count, &public_key, &private_key)
        assertRV(retval)

        return (make_object(session, public_key),
                make_object(session, private_key))


class LocalDomainParameters(GenerateWithParametersMixin, types.LocalDomainParameters):
    pass

class StoredDomainParameters(GenerateWithParametersMixin):
    pass

class Certificate(types.Certificate):
    pass


class EncryptMixin(types.EncryptMixin):
    """Expand EncryptMixin with an implementation."""

    def _encrypt(self, data,
                 mechanism=None, mechanism_param=None):
        """
        Non chunking encrypt. Needed for some mechanisms.
        """
        mech = MechanismWithParam(
            self.key_type, DEFAULT_ENCRYPT_MECHANISMS,
            mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE key = self.handle
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef CK_BYTE [:] ciphertext
        cdef CK_ULONG length
        cdef CK_RV retval

        with session.operation_lock:
            with nogil:
                retval = session.funclist.C_EncryptInit(session.handle, mech_data, key)
            assertRV(retval)

            # Call to find out the buffer length
            with nogil:
                retval = session.funclist.C_Encrypt(session.handle, data_ptr, data_len, NULL, &length)
            assertRV(retval)

            ciphertext = CK_BYTE_buffer(length)

            with nogil:
                retval = session.funclist.C_Encrypt(session.handle, data_ptr, data_len, &ciphertext[0], &length)
            assertRV(retval)

            return bytes(ciphertext[:length])


    def _encrypt_generator(self, data,
                           mechanism=None, mechanism_param=None,
                           buffer_size=8192):
        """
        Do chunked encryption.

        Failing to consume the generator will raise GeneratorExit when it
        garbage collects. This will release the lock, but you'll still be
        in the middle of an operation, and all future operations will raise
        OperationActive, see tests/test_iterators.py:test_close_iterators().

        FIXME: cancel the operation when we exit the generator early.
        """
        mech = MechanismWithParam(
            self.key_type, DEFAULT_ENCRYPT_MECHANISMS,
            mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE key = self.handle
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len
        cdef CK_ULONG length
        cdef CK_BYTE [:] part_out = CK_BYTE_buffer(buffer_size)
        cdef CK_RV retval

        with session.operation_lock:
            with nogil:
                retval = session.funclist.C_EncryptInit(session.handle, mech_data, key)
            assertRV(retval)

            for part_in in data:
                if not part_in:
                    continue

                data_ptr = part_in
                data_len = <CK_ULONG> len(part_in)
                length = buffer_size

                with nogil:
                    retval = session.funclist.C_EncryptUpdate(session.handle, data_ptr, data_len, &part_out[0], &length)
                assertRV(retval)

                yield bytes(part_out[:length])

            # Finalize
            # We assume the buffer is much bigger than the block size
            length = buffer_size

            with nogil:
                retval = session.funclist.C_EncryptFinal(session.handle, &part_out[0], &length)
            assertRV(retval)

            yield bytes(part_out[:length])


class DecryptMixin(types.DecryptMixin):
    """Expand DecryptMixin with an implementation."""

    def _decrypt(self, data,
                 mechanism=None, mechanism_param=None, pin=None):
        """Non chunking decrypt."""
        mech = MechanismWithParam(
            self.key_type, DEFAULT_ENCRYPT_MECHANISMS,
            mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE key = self.handle
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef CK_BYTE [:] plaintext
        cdef CK_ULONG length
        cdef CK_USER_TYPE user_type
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length
        cdef CK_RV retval

        if pin is not None:
            pin = pin.encode('utf-8')
            pin_data = pin
            pin_length = <CK_ULONG> len(pin)
            user_type = CKU_CONTEXT_SPECIFIC

        with session.operation_lock:
            with nogil:
                retval = session.funclist.C_DecryptInit(session.handle, mech_data, key)
            assertRV(retval)

            # Log in if pin provided
            if pin is not None:
                with nogil:
                    retval = session.funclist.C_Login(session.handle, user_type, pin_data, pin_length)
                assertRV(retval)

            # Call to find out the buffer length
            with nogil:
                retval = session.funclist.C_Decrypt(session.handle, data_ptr, data_len, NULL, &length)
            assertRV(retval)

            plaintext = CK_BYTE_buffer(length)

            with nogil:
                retval = session.funclist.C_Decrypt(session.handle, data_ptr, data_len, &plaintext[0], &length)
            assertRV(retval)

            return bytes(plaintext[:length])


    def _decrypt_generator(self, data,
                           mechanism=None, mechanism_param=None, pin=None,
                           buffer_size=8192):
        """
        Chunking decrypt.

        Failing to consume the generator will raise GeneratorExit when it
        garbage collects. This will release the lock, but you'll still be
        in the middle of an operation, and all future operations will raise
        OperationActive, see tests/test_iterators.py:test_close_iterators().

        FIXME: cancel the operation when we exit the generator early.
        """
        mech = MechanismWithParam(
            self.key_type, DEFAULT_ENCRYPT_MECHANISMS,
            mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE key = self.handle
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len
        cdef CK_ULONG length
        cdef CK_BYTE [:] part_out = CK_BYTE_buffer(buffer_size)
        cdef CK_USER_TYPE user_type
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length
        cdef CK_RV retval

        if pin is not None:
            pin = pin.encode('utf-8')
            pin_data = pin
            pin_length = <CK_ULONG> len(pin)
            user_type = CKU_CONTEXT_SPECIFIC

        with session.operation_lock:
            with nogil:
                retval = session.funclist.C_DecryptInit(session.handle, mech_data, key)
            assertRV(retval)

            # Log in if pin provided
            if pin is not None:
                with nogil:
                    retval = session.funclist.C_Login(session.handle, user_type, pin_data, pin_length)
                assertRV(retval)

            for part_in in data:
                if not part_in:
                    continue

                data_ptr = part_in
                data_len = <CK_ULONG> len(part_in)
                length = buffer_size

                with nogil:
                    retval = session.funclist.C_DecryptUpdate(session.handle, data_ptr, data_len, &part_out[0], &length)
                assertRV(retval)

                yield bytes(part_out[:length])

            # Finalize
            # We assume the buffer is much bigger than the block size
            length = buffer_size

            with nogil:
                retval = session.funclist.C_DecryptFinal(session.handle, &part_out[0], &length)
            assertRV(retval)

            yield bytes(part_out[:length])


class SignMixin(types.SignMixin):
    """Expand SignMixin with an implementation."""

    def _sign(self, data,
              mechanism=None, mechanism_param=None, pin=None):

        mech = MechanismWithParam(
            self.key_type, DEFAULT_SIGN_MECHANISMS,
            mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE key = self.handle
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef CK_BYTE [:] signature
        cdef CK_ULONG length
        cdef CK_USER_TYPE user_type
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length
        cdef CK_RV retval

        if pin is not None:
            pin = pin.encode('utf-8')
            pin_data = pin
            pin_length = <CK_ULONG> len(pin)
            user_type = CKU_CONTEXT_SPECIFIC

        with session.operation_lock:
            with nogil:
                retval = session.funclist.C_SignInit(session.handle, mech_data, key)
            assertRV(retval)

            # Log in if pin provided
            if pin is not None:
                with nogil:
                    retval = session.funclist.C_Login(session.handle, user_type, pin_data, pin_length)
                assertRV(retval)

            # Call to find out the buffer length
            with nogil:
                retval = session.funclist.C_Sign(session.handle, data_ptr, data_len, NULL, &length)
            assertRV(retval)

            signature = CK_BYTE_buffer(length)

            with nogil:
                retval = session.funclist.C_Sign(session.handle, data_ptr, data_len, &signature[0], &length)
            assertRV(retval)

            return bytes(signature[:length])

    def _sign_generator(self, data,
                        mechanism=None, mechanism_param=None, pin=None):

        mech = MechanismWithParam(
            self.key_type, DEFAULT_SIGN_MECHANISMS,
            mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE key = self.handle
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len
        cdef CK_BYTE [:] signature
        cdef CK_ULONG length
        cdef CK_USER_TYPE user_type
        cdef CK_UTF8CHAR *pin_data
        cdef CK_ULONG pin_length
        cdef CK_RV retval

        if pin is not None:
            pin = pin.encode('utf-8')
            pin_data = pin
            pin_length = <CK_ULONG> len(pin)
            user_type = CKU_CONTEXT_SPECIFIC

        with session.operation_lock:
            with nogil:
                retval = session.funclist.C_SignInit(session.handle, mech_data, key)
            assertRV(retval)

            # Log in if pin provided
            if pin is not None:
                with nogil:
                    retval = session.funclist.C_Login(session.handle, user_type, pin_data, pin_length)
                assertRV(retval)

            for part_in in data:
                if not part_in:
                    continue

                data_ptr = part_in
                data_len = <CK_ULONG> len(part_in)

                with nogil:
                    retval = session.funclist.C_SignUpdate(session.handle, data_ptr, data_len)
                assertRV(retval)

            # Finalize
            # Call to find out the buffer length
            with nogil:
                retval = session.funclist.C_SignFinal(session.handle, NULL, &length)
            assertRV(retval)

            signature = CK_BYTE_buffer(length)

            with nogil:
                retval = session.funclist.C_SignFinal(session.handle, &signature[0], &length)
            assertRV(retval)

            return bytes(signature[:length])


class VerifyMixin(types.VerifyMixin):
    """Expand VerifyMixin with an implementation."""

    def _verify(self, data, signature,
                mechanism=None, mechanism_param=None):

        mech = MechanismWithParam(
            self.key_type, DEFAULT_SIGN_MECHANISMS,
            mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE key = self.handle
        cdef CK_BYTE *data_ptr = data
        cdef CK_ULONG data_len = <CK_ULONG> len(data)
        cdef CK_BYTE *sig_ptr = signature
        cdef CK_ULONG sig_len = <CK_ULONG> len(signature)
        cdef CK_RV retval

        with session.operation_lock:
            with nogil:
                retval = session.funclist.C_VerifyInit(session.handle, mech_data, key)
            assertRV(retval)

            with nogil:
                retval = session.funclist.C_Verify(session.handle, data_ptr, data_len, sig_ptr, sig_len)
            assertRV(retval)

    def _verify_generator(self, data, signature,
                          mechanism=None, mechanism_param=None):

        mech = MechanismWithParam(
            self.key_type, DEFAULT_SIGN_MECHANISMS,
            mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE key = self.handle
        cdef CK_BYTE *data_ptr
        cdef CK_ULONG data_len
        cdef CK_BYTE *sig_ptr = signature
        cdef CK_ULONG sig_len = <CK_ULONG> len(signature)
        cdef CK_RV retval

        with session.operation_lock:
            with nogil:
                retval = session.funclist.C_VerifyInit(session.handle, mech_data, key)
            assertRV(retval)

            for part_in in data:
                if not part_in:
                    continue

                data_ptr = part_in
                data_len = <CK_ULONG> len(part_in)

                with nogil:
                    retval = session.funclist.C_VerifyUpdate(session.handle, data_ptr, data_len)
                assertRV(retval)

            with nogil:
                retval = session.funclist.C_VerifyFinal(session.handle, sig_ptr, sig_len)
            assertRV(retval)


class WrapMixin(types.WrapMixin):
    """Expand WrapMixin with an implementation."""

    def wrap_key(self, key,
                 mechanism=None, mechanism_param=None):

        if not isinstance(key, types.Key):
            raise ArgumentsBad("`key` must be a Key.")

        mech = MechanismWithParam(
            self.key_type, DEFAULT_WRAP_MECHANISMS,
            mechanism, mechanism_param)

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE wrapping_key = self.handle
        cdef CK_OBJECT_HANDLE key_to_wrap = key.handle
        cdef CK_ULONG length
        cdef CK_RV retval

        # Find out how many bytes we need to allocate
        with nogil:
            retval = session.funclist.C_WrapKey(session.handle, mech_data, wrapping_key, key_to_wrap, NULL, &length)
        assertRV(retval)

        cdef CK_BYTE [:] data = CK_BYTE_buffer(length)

        with nogil:
            retval = session.funclist.C_WrapKey(session.handle, mech_data, wrapping_key, key_to_wrap, &data[0], &length)
        assertRV(retval)

        return bytes(data[:length])


class UnwrapMixin(types.UnwrapMixin):
    """Expand UnwrapMixin with an implementation."""

    def unwrap_key(self, object_class, key_type, key_data,
                   id=None, label=None,
                   mechanism=None, mechanism_param=None,
                   store=False, capabilities=None,
                   template=None):

        if not isinstance(object_class, ObjectClass):
            raise ArgumentsBad("`object_class` must be ObjectClass.")

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(
            self.key_type, DEFAULT_WRAP_MECHANISMS,
            mechanism, mechanism_param)

        # Build attributes
        template_ = {
            Attribute.CLASS: object_class,
            Attribute.KEY_TYPE: key_type,
            Attribute.ID: id or b'',
            Attribute.LABEL: label or '',
            Attribute.TOKEN: store,
            # Capabilities
            Attribute.ENCRYPT: MechanismFlag.ENCRYPT & capabilities,
            Attribute.DECRYPT: MechanismFlag.DECRYPT & capabilities,
            Attribute.WRAP: MechanismFlag.WRAP & capabilities,
            Attribute.UNWRAP: MechanismFlag.UNWRAP & capabilities,
            Attribute.SIGN: MechanismFlag.SIGN & capabilities,
            Attribute.VERIFY: MechanismFlag.VERIFY & capabilities,
            Attribute.DERIVE: MechanismFlag.DERIVE & capabilities,
        }
        attrs = AttributeList(merge_templates(template_, template))

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE unwrapping_key = self.handle
        cdef CK_BYTE *wrapped_key_ptr = key_data
        cdef CK_ULONG wrapped_key_len = <CK_ULONG> len(key_data)
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key
        cdef CK_RV retval

        with nogil:
            retval = session.funclist.C_UnwrapKey(session.handle, mech_data, unwrapping_key, wrapped_key_ptr, wrapped_key_len, attr_data, attr_count, &key)
        assertRV(retval)

        return make_object(session, key)


class DeriveMixin(types.DeriveMixin):
    """Expand DeriveMixin with an implementation."""

    def derive_key(self, key_type, key_length,
                   id=None, label=None,
                   store=False, capabilities=None,
                   mechanism=None, mechanism_param=None,
                   template=None):

        if not isinstance(key_type, KeyType):
            raise ArgumentsBad("`key_type` must be KeyType.")

        if not isinstance(key_length, int):
            raise ArgumentsBad("`key_length` is the length in bits.")

        if capabilities is None:
            try:
                capabilities = DEFAULT_KEY_CAPABILITIES[key_type]
            except KeyError:
                raise ArgumentsBad("No default capabilities for this key "
                                   "type. Please specify `capabilities`.")

        mech = MechanismWithParam(
            self.key_type, DEFAULT_DERIVE_MECHANISMS,
            mechanism, mechanism_param)

        # Build attributes
        template_ = {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: key_type,
            Attribute.ID: id or b'',
            Attribute.LABEL: label or '',
            Attribute.TOKEN: store,
            Attribute.VALUE_LEN: key_length // 8,  # In bytes
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
        attrs = AttributeList(merge_templates(template_, template))

        cdef Session session = self.session
        cdef CK_MECHANISM *mech_data = mech.data
        cdef CK_OBJECT_HANDLE src_key = self.handle
        cdef CK_ATTRIBUTE *attr_data = attrs.data
        cdef CK_ULONG attr_count = attrs.count
        cdef CK_OBJECT_HANDLE key
        cdef CK_RV retval

        with nogil:
            retval = session.funclist.C_DeriveKey(session.handle, mech_data, src_key, attr_data, attr_count, &key)
        assertRV(retval)

        return make_object(session, key)


_CLASS_MAP = {
    ObjectClass.SECRET_KEY: SecretKey,
    ObjectClass.PUBLIC_KEY: PublicKey,
    ObjectClass.PRIVATE_KEY: PrivateKey,
    ObjectClass.DOMAIN_PARAMETERS: StoredDomainParameters,
    ObjectClass.CERTIFICATE: Certificate,
}

cdef extern from "../extern/load_module.c":
    ctypedef struct P11_HANDLE:
        void *get_function_list_ptr

    object p11_error()
    P11_HANDLE* p11_open(object path_str)
    int p11_close(P11_HANDLE* handle)


cdef class lib(HasFuncList):
    """
    Main entry point.

    This class needs to be defined cdef, so it can't shadow a class in
    pkcs11.types.
    """

    cdef readonly str so
    cdef readonly str manufacturer_id
    cdef readonly str library_description
    cdef readonly tuple cryptoki_version
    cdef readonly tuple library_version
    cdef readonly bint initialized
    cdef P11_HANDLE *_p11_handle

    cdef _load_pkcs11_lib(self, so) with gil:
        """Load a PKCS#11 library, and extract function calls.

        This method will dynamically load a PKCS11 library, and attempt to
        resolve the symbol 'C_GetFunctionList()'. Once found, the entry point
        is called to populate an internal table of function pointers.

        This is a private method, and must never be called directly.
        Called when a new lib class is instantiated.

        :param so: the path to a valid PKCS#11 library
        :type so: str
        :raises: RuntimeError or PKCS11Error
        :rtype: None
        """

        # to keep a pointer to the C_GetFunctionList address returned by dlsym()
        cdef C_GetFunctionList_ptr populate_function_list
        cdef CK_RV retval

        cdef P11_HANDLE *handle = p11_open(so)
        if handle == NULL:
            err = <str> p11_error()
            if err:
                raise RuntimeError(f"OS exception while loading {so}: {err}")
            else:
                raise RuntimeError(f"Unknown exception while loading {so}")
        populate_function_list = <C_GetFunctionList_ptr> handle.get_function_list_ptr
        self._p11_handle = handle

        assertRV(populate_function_list(&self.funclist))


    def __cinit__(self, so):
        cdef CK_RV retval
        self._p11_handle = NULL
        self._load_pkcs11_lib(so)
        self.initialized = False
        # at this point, _funclist contains all function pointers to the library

    cpdef initialize(self):
        cdef CK_RV retval
        if self.funclist != NULL and not self.initialized:
            with nogil:
                retval = self.funclist.C_Initialize(NULL)
            assertRV(retval)
            self.initialized = True

    cpdef finalize(self):
        cdef CK_RV retval
        if self.funclist != NULL and self.initialized:
            with nogil:
                retval = self.funclist.C_Finalize(NULL)
            assertRV(retval)
            self.initialized = False

    def reinitialize(self):
        if self.funclist != NULL:
            self.finalize()
            self.initialize()

    def __init__(self, so):
        self.so = so
        cdef CK_INFO info
        cdef CK_RV retval

        self.initialize()

        with nogil:
            retval = self.funclist.C_GetInfo(&info)
        assertRV(retval)

        manufacturerID = info.manufacturerID[:sizeof(info.manufacturerID)]
        libraryDescription = info.libraryDescription[:sizeof(info.libraryDescription)]

        self.manufacturer_id = _CK_UTF8CHAR_to_str(manufacturerID)
        self.library_description = _CK_UTF8CHAR_to_str(libraryDescription)
        self.cryptoki_version = _CK_VERSION_to_tuple(info.cryptokiVersion)
        self.library_version = _CK_VERSION_to_tuple(info.libraryVersion)

    def __str__(self):
        return '\n'.join((
            "Library: %s" % self.so,
            "Manufacturer ID: %s" % self.manufacturer_id,
            "Library Description: %s" % self.library_description,
            "Cryptoki Version: %s.%s" % self.cryptoki_version,
            "Library Version: %s.%s" % self.library_version,
        ))

    def __repr__(self):
        return '<pkcs11.lib ({so})>'.format(
            so=self.so)


    def get_slots(self, token_present=False):
        """Get all slots."""

        cdef CK_BBOOL present = token_present
        cdef CK_ULONG count
        cdef CK_RV retval

        with nogil:
            retval = self.funclist.C_GetSlotList(present, NULL, &count)
        assertRV(retval)

        if count == 0:
            return []

        cdef CK_SLOT_ID [:] slot_list = CK_ULONG_buffer(count)

        with nogil:
            retval = self.funclist.C_GetSlotList(present, &slot_list[0], &count)
        assertRV(retval)

        cdef CK_SLOT_ID slot_id
        cdef CK_SLOT_INFO info

        slots = []

        for slot_id in slot_list:
            with nogil:
                retval = self.funclist.C_GetSlotInfo(slot_id, &info)
            assertRV(retval)

            slots.append(
                Slot.make(self.funclist, slot_id, info)
            )

        return slots


    def get_tokens(self,
                   token_label=None,
                   token_serial=None,
                   token_flags=None,
                   slot_flags=None,
                   mechanisms=None):
        """Search for a token matching the parameters."""

        for slot in self.get_slots():
            try:
                token = slot.get_token()
                token_mechanisms = slot.get_mechanisms()
            
                if token_label is not None and \
                        token.label != token_label:
                    continue

                if token_serial is not None and \
                        token.serial != token_serial:
                    continue

                if token_flags is not None and \
                        not token.flags & token_flags:
                    continue

                if slot_flags is not None and \
                        not slot.flags & slot_flags:
                    continue

                if mechanisms is not None and \
                        set(mechanisms) not in token_mechanisms:
                    continue

                yield token
            except (TokenNotPresent, TokenNotRecognised):
                continue

    def get_token(self, **kwargs):
        """Get a single token."""
        iterator = self.get_tokens(**kwargs)

        try:
            token = next(iterator)
        except StopIteration:
            raise NoSuchToken("No token matching %s" % kwargs)

        try:
            next(iterator)
            raise MultipleTokensReturned(
                "More than 1 token matches %s" % kwargs)
        except StopIteration:
            return token

    def wait_for_slot_event(self, blocking=True):
        cdef CK_SLOT_ID slot_id
        cdef CK_FLAGS flag = 0
        cdef CK_RV retval

        if not blocking:
            flag |= CKF_DONT_BLOCK

        with nogil:
            retval = self.funclist.C_WaitForSlotEvent(flag, &slot_id, NULL)
        assertRV(retval)

        cdef CK_SLOT_INFO info

        with nogil:
            retval = self.funclist.C_GetSlotInfo(slot_id, &info)
        assertRV(retval)

        slotDescription = info.slotDescription[:sizeof(info.slotDescription)]
        manufacturerID = info.manufacturerID[:sizeof(info.manufacturerID)]

        return Slot(self, slot_id, slotDescription, manufacturerID,
                 info.hardwareVersion, info.firmwareVersion, info.flags)

    def __dealloc__(self):
        self.finalize()
        self.funclist = NULL
        if self._p11_handle != NULL:
            p11_close(self._p11_handle)
