"""Bounded, synchronous ctypes adapter for the pinned experimental HiChain ABI.

Native callbacks enqueue packets; callers route them after receive_data returns.
One Runtime owns the process-global HUKS store. No credentials are logged here.
"""
import ctypes as C
import hashlib
import os
from pathlib import Path
import secrets

U32 = C.c_uint32
I32 = C.c_int32
PTR = C.c_void_p


def blob_type(name, size):
    return type(name, (C.Structure,), {'_fields_': [('length', U32), ('value', C.c_ubyte * size)]})


AuthId = blob_type('AuthId', 64)
Pin = blob_type('Pin', 16)
Key = blob_type('Key', 128)
Name = blob_type('Name', 256)


class Parameters(C.Structure):
    _fields_ = [('self_id', AuthId), ('peer_id', AuthId), ('key_length', U32)]


class Identity(C.Structure):
    _fields_ = [('session_id', U32), ('package', Name), ('service', Name), ('context', PTR)]


class Buffer(C.Structure):
    _fields_ = [('value', PTR), ('size', U32), ('length', U32)]


Transmit = C.CFUNCTYPE(None, PTR, PTR, U32)
GetParams = C.CFUNCTYPE(None, PTR, I32, C.POINTER(Pin), C.POINTER(Parameters))
SetKey = C.CFUNCTYPE(None, PTR, C.POINTER(Key))
SetResult = C.CFUNCTYPE(None, PTR, I32)
Confirm = C.CFUNCTYPE(I32, PTR, I32)


class Callbacks(C.Structure):
    _fields_ = [('transmit', Transmit), ('params', GetParams), ('key', SetKey),
                ('result', SetResult), ('confirm', Confirm)]


Read = C.CFUNCTYPE(I32, C.c_char_p, U32, PTR, U32)
Write = C.CFUNCTYPE(I32, C.c_char_p, U32, PTR, U32)
FileSize = C.CFUNCTYPE(I32, C.c_char_p)
Udid = C.CFUNCTYPE(I32, PTR, U32)


class Files(C.Structure):
    _fields_ = [('read', Read), ('write', Write), ('size', FileSize)]


def fill(target, data):
    if not 0 < len(data) <= len(target.value):
        raise ValueError('invalid native parameter length')
    target.length = len(data)
    target.value[:len(data)] = data


class Runtime:
    """Create once per process, before any Session; callbacks remain alive."""
    _active = None

    def __init__(self, library, store, device_id):
        if Runtime._active is not None:
            raise RuntimeError('HUKS runtime already initialized')
        self.root = Path(store)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or (os.name == 'posix' and self.root.stat().st_mode & 0o077):
            raise ValueError('HUKS store must be a private directory')
        self.lib = C.CDLL(str(Path(library).resolve()))
        self.lib.carlink_abi_size.argtypes = [C.c_char_p]
        self.lib.carlink_abi_size.restype = C.c_size_t
        for name, struct in [('session_identity', Identity), ('hc_call_back', Callbacks),
                             ('operation_parameter', Parameters), ('hc_pin', Pin),
                             ('hc_session_key', Key), ('uint8_buff', Buffer)]:
            if self.lib.carlink_abi_size(name.encode()) != C.sizeof(struct):
                raise RuntimeError('incompatible HiChain ABI: ' + name)
        self.file_callbacks = Files(Read(self.read), Write(self.write), FileSize(self.size))
        self.udid_bytes = hashlib.sha256(device_id.encode('utf-8')).digest()
        self.udid_callback = Udid(self.udid)
        self.lib.hks_register_file_callbacks.argtypes = [C.POINTER(Files)]
        self.lib.hks_register_get_hardware_udid_callback.argtypes = [Udid]
        for code in (self.lib.hks_register_file_callbacks(C.byref(self.file_callbacks)),
                     self.lib.hks_register_get_hardware_udid_callback(self.udid_callback)):
            if code:
                raise RuntimeError('HUKS callback registration failed: ' + str(code))
        self.lib.get_instance.argtypes = [C.POINTER(Identity), I32, C.POINTER(Callbacks)]
        self.lib.get_instance.restype = PTR
        self.lib.destroy.argtypes = [C.POINTER(PTR)]
        self.lib.destroy.restype = None
        self.lib.receive_data.argtypes = [PTR, C.POINTER(Buffer)]
        self.lib.start_pake.argtypes = [PTR, C.POINTER(Parameters)]
        self.lib.authenticate_peer.argtypes = [PTR, C.POINTER(Parameters)]
        Runtime._active = self

    def path(self, name):
        if name not in (b'info1.data', b'info2.data', b'hks_keystore'):
            raise ValueError('unexpected HUKS filename')
        return self.root / name.decode('ascii')

    def open(self, name, flags):
        return os.open(self.path(name), flags | getattr(os, 'O_NOFOLLOW', 0), 0o600)

    def read(self, name, offset, buf, length):
        try:
            if offset + length > 1048576:
                return -1
            try:
                fd = self.open(name, os.O_RDONLY)
            except FileNotFoundError:
                return 0
            with os.fdopen(fd, 'rb') as file:
                file.seek(offset)
                data = file.read(length)
            C.memmove(buf, data, len(data))
            return len(data)
        except Exception:
            return -1

    def write(self, name, offset, buf, length):
        try:
            if offset + length > 1048576:
                return -1
            fd = self.open(name, os.O_RDWR | os.O_CREAT)
            with os.fdopen(fd, 'r+b') as file:
                file.seek(offset)
                file.write(C.string_at(buf, length))
                file.flush()
                os.fsync(file.fileno())
            return 0
        except Exception:
            return -1

    def size(self, name):
        try:
            fd = self.open(name, os.O_RDONLY)
            try:
                size = os.fstat(fd).st_size
                return size if size <= 1048576 else -1
            finally:
                os.close(fd)
        except FileNotFoundError:
            return 0
        except Exception:
            return -1

    def udid(self, buf, length):
        if length != len(self.udid_bytes):
            return -1
        C.memmove(buf, self.udid_bytes, length)
        return 0


class Session:
    def __init__(self, runtime, self_id, peer_id, pin, role=2,
                 package='com.huawei.authagent', service='SFXTEST'):
        if len(pin) != 6 or not pin.isascii() or not pin.isdigit():
            raise ValueError('PIN must contain six ASCII digits')
        self.runtime = runtime
        self.params = Parameters()
        fill(self.params.self_id, self_id.encode('utf-8'))
        fill(self.params.peer_id, peer_id.encode('utf-8'))
        self.params.key_length = 32
        self.pin = Pin()
        fill(self.pin, pin.encode('ascii'))
        self.identity = Identity()
        self.identity.session_id = secrets.randbits(32)
        fill(self.identity.package, package.encode('ascii'))
        fill(self.identity.service, service.encode('ascii'))
        self.pending = []
        self.results = []
        self.session_key = None
        self.callback_error = False
        self.callbacks = Callbacks(Transmit(self.transmit), GetParams(self.get_params),
                                   SetKey(self.set_key), SetResult(self.set_result),
                                   Confirm(lambda _, op: 0 if op in (1, 2) else -1))
        self.handle = PTR(runtime.lib.get_instance(C.byref(self.identity), role, C.byref(self.callbacks)))
        if not self.handle:
            raise RuntimeError('HiChain instance initialization failed')

    def transmit(self, _, data, length):
        if not 0 < length <= 65536 or len(self.pending) >= 8:
            self.callback_error = True
        else:
            try:
                import json
                packet = json.loads(C.string_at(data, length))
                if not isinstance(packet, dict):
                    raise ValueError('native authentication output must be an object')
                payload = packet.get('payload', {})
                if isinstance(payload, dict):
                    # Legacy serializers quote these integers, while their own
                    # parsers and current phones expect JSON numeric values.
                    for name in ('peerUserType', 'keyLength'):
                        value = payload.get(name)
                        if isinstance(value, str) and value in ('0', '1', '16', '32'):
                            payload[name] = int(value)
                self.pending.append(json.dumps(packet, separators=(',', ':')).encode('utf-8'))
            except (ValueError, TypeError, UnicodeError):
                self.callback_error = True

    def get_params(self, _, operation, pin, params):
        # start_pake builds its object before assigning BIND, so its initial
        # parameter callback uses NO_OPERATION_CODE (0).
        if operation not in (0, 1, 2, 99):
            self.callback_error = True
            return
        C.memmove(pin, C.byref(self.pin), C.sizeof(self.pin))
        C.memmove(params, C.byref(self.params), C.sizeof(self.params))

    def set_key(self, _, key):
        if 0 < key.contents.length <= 128:
            self.session_key = bytes(key.contents.value[:key.contents.length])
        else:
            self.callback_error = True

    def set_result(self, _, result):
        if len(self.results) >= 64:
            self.callback_error = True
        else:
            self.results.append(result)

    def take(self, code):
        if self.callback_error:
            raise RuntimeError('invalid HiChain callback')
        packets, self.pending = self.pending, []
        return code, packets

    def receive(self, data):
        if not self.handle or not 0 < len(data) <= 65536:
            raise ValueError('invalid HiChain input')
        # A trusted STS request may negotiate a shorter returned service key
        # than the initial PAKE binding. Honor the peer's explicit length.
        import json
        request = json.loads(data)
        payload = request.get('payload', {})
        if isinstance(payload, dict) and payload.get('peerUserType') in ('0', '1'):
            payload['peerUserType'] = int(payload['peerUserType'])
            data = json.dumps(request, separators=(',', ':')).encode('utf-8')
        if request.get('message') == 17:
            length = request.get('payload', {}).get('keyLength')
            if isinstance(length, str) and length in ('16', '32'):
                length = int(length)
            if type(length) is not int or length not in (16, 32):
                raise ValueError('unsupported authenticated key length')
            self.params.key_length = length
        raw = C.create_string_buffer(data)
        buffer = Buffer(C.cast(raw, PTR), len(data), len(data))
        return self.take(self.runtime.lib.receive_data(self.handle, C.byref(buffer)))

    def start(self):
        return self.take(self.runtime.lib.start_pake(self.handle, C.byref(self.params)))

    def authenticate(self, key_length=16):
        if key_length not in (16, 32):
            raise ValueError('unsupported authenticated key length')
        self.params.key_length = key_length
        return self.take(self.runtime.lib.authenticate_peer(self.handle, C.byref(self.params)))

    def close(self):
        if self.handle:
            self.runtime.lib.destroy(C.byref(self.handle))
        self.session_key = None
        C.memset(C.byref(self.pin), 0, C.sizeof(self.pin))
