"""Public RFC 8032 vector and exported C ABI checks; no device credentials."""
import ctypes as C
import json
from pathlib import Path
import sys

lib = C.CDLL(str(Path(sys.argv[1]).resolve()))
lib.ED25519_public_from_private.argtypes = [C.c_void_p, C.c_void_p]
lib.ED25519_public_from_private.restype = None
lib.ED25519_sign.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p]
lib.ED25519_sign.restype = C.c_int
lib.ED25519_verify.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p]
lib.ED25519_verify.restype = C.c_int
# RFC 8032 section 7.1, TEST 1, empty message.
seed = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
expected_public = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
expected_signature = bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
                                  '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
public = C.create_string_buffer(32)
lib.ED25519_public_from_private(public, seed)
assert public.raw == expected_public
signature = C.create_string_buffer(64)
assert lib.ED25519_sign(signature, b'', 0, public, seed + expected_public) == 1
assert signature.raw == expected_signature
assert lib.ED25519_verify(b'', 0, signature, public) == 1
bad = bytearray(signature.raw); bad[0] ^= 1
assert lib.ED25519_verify(b'', 0, bytes(bad), public) == 0
for symbol in ('get_instance', 'destroy', 'receive_data', 'start_pake', 'authenticate_peer',
               'hks_register_file_callbacks', 'hks_register_get_hardware_udid_callback'):
    assert getattr(lib, symbol)
print(json.dumps({'ed25519_rfc8032': 'pass', 'tampered_signature': 'rejected',
                  'required_symbols': 'present'}))
