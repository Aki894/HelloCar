"""DMSDP per-record AES-128-CTR using the system OpenSSL EVP API.

Observed envelope: fresh 16-byte IV followed by CTR ciphertext. The native
receiver takes the first 16 bytes of the authenticated HiChain session key.
This legacy envelope has no separate authentication tag.
"""
import ctypes as C
from ctypes.util import find_library
import os
from pathlib import Path
import sys
from nearby_wire import ProtocolError


class Cipher:
    def __init__(self, session_key, max_record=1500):
        if not isinstance(session_key, bytes) or len(session_key) not in (16, 32):
            raise ProtocolError('invalid authenticated session key length')
        self.key = bytearray(session_key[:16])
        if not 17 <= max_record <= 10 * 1024 * 1024:
            raise ProtocolError('invalid cipher record limit')
        self.max_record = max_record
        library = find_library('crypto')
        if not library and sys.platform == 'win32':
            library = str(Path(sys.prefix) / 'Library/bin/libcrypto-3-x64.dll')
        self.lib = C.CDLL(library or 'libcrypto.so.3')
        self.lib.EVP_CIPHER_CTX_new.restype = C.c_void_p
        self.lib.EVP_CIPHER_CTX_free.argtypes = [C.c_void_p]
        self.lib.EVP_aes_128_ctr.restype = C.c_void_p
        self.lib.EVP_EncryptInit_ex.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p,
                                              C.c_void_p, C.c_void_p]
        self.lib.EVP_EncryptUpdate.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_int),
                                             C.c_void_p, C.c_int]
        self.lib.EVP_EncryptFinal_ex.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_int)]

    def transform(self, data, iv):
        if self.key is None or len(iv) != 16 or not 0 < len(data) < self.max_record:
            raise ProtocolError('invalid cipher record')
        context = self.lib.EVP_CIPHER_CTX_new()
        if not context:
            raise ProtocolError('cannot allocate cipher context')
        try:
            output = C.create_string_buffer(len(data) + 16)
            count, final = C.c_int(), C.c_int()
            if (self.lib.EVP_EncryptInit_ex(context, self.lib.EVP_aes_128_ctr(), None,
                                            bytes(self.key), iv) != 1
                    or self.lib.EVP_EncryptUpdate(context, output, C.byref(count),
                                                 data, len(data)) != 1
                    or self.lib.EVP_EncryptFinal_ex(context, C.byref(output, count.value),
                                                   C.byref(final)) != 1):
                raise ProtocolError('cipher operation failed')
            if count.value + final.value != len(data):
                raise ProtocolError('unexpected cipher output length')
            return output.raw[:len(data)]
        finally:
            self.lib.EVP_CIPHER_CTX_free(context)

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        return iv + self.transform(plaintext, iv)

    def decrypt(self, record):
        if not 16 < len(record) < self.max_record:
            raise ProtocolError('invalid encrypted record length')
        return self.transform(record[16:], record[:16])

    def close(self):
        if self.key is not None:
            self.key[:] = b'\0' * len(self.key)
            self.key = None
