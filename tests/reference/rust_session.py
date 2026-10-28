"""Temporary BlueZ/media adapter for Rust R2 connection state.

No secret data is passed in argv, stdout or stderr. The child owns HiChain and
the old Python media adapter receives its session key over a private socketpair.
"""
import dataclasses
import hashlib
import json
import os
import socket
import struct
import subprocess
import threading
import time

from auth_wire import AuthError
from nearby_wire import ProtocolError

LIMIT = 256 * 1024


class Worker:
    def __init__(self, executable, identity_path, model, address, library, store,
                 offer, summary, business_channel, runner=()):
        self.socket, child = socket.socketpair()
        self.socket.settimeout(10)
        self.lock = threading.Lock()
        self.process = None
        self.closed = False
        self.auth_generation = None
        try:
            # Only the child's one IPC descriptor survives exec. CLI diagnostic
            # output cannot become protocol data or expose the key in our logs.
            self.process = subprocess.Popen([*runner, executable,  'session-worker', str(child.fileno())],
                pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child.close()
            ready = self.call(dict(identity=str(identity_path), model=model, address=address,
                                  library=str(library), store=str(store),
                                  offer=dataclasses.asdict(offer), business_channel=business_channel))
            if (not ready.get('ready') or ready.get('wire_identity_sha256') !=
                    hashlib.sha256(summary).hexdigest()):
                raise RuntimeError('Rust signing identity does not match the existing adapter')
        except BaseException:
            child.close()
            self.close()
            raise

    def _read(self, size):
        output = bytearray()
        while len(output) < size:
            part = self.socket.recv(size - len(output))
            if not part:
                raise RuntimeError('Rust connection worker closed')
            output.extend(part)
        return output

    def call(self, command):
        with self.lock:
            if self.closed:
                raise RuntimeError('Rust connection worker is closed')
            data = json.dumps(command, separators=(',', ':'), ensure_ascii=False).encode()
            if not 0 < len(data) <= LIMIT:
                raise ValueError('Rust IPC message exceeds limit')
            self.socket.sendall(struct.pack('!I', len(data)) + data)
            size, = struct.unpack('!I', self._read(4))
            if not 0 < size <= LIMIT:
                raise ValueError('Rust IPC response exceeds limit')
            result = json.loads(self._read(size))
            if result.get('ok') is not True:
                # Never interpolate the input packet, PIN, key or child response.
                raise ProtocolError('Rust connection protocol: ' + result.get('error', 'request rejected'))
            return result

    def close(self):
        # A broken frame or cancelled parent always closes the private endpoint;
        # the child observes EOF and drops its session, keys and HUKS runtime.
        if self.closed:
            return
        self.closed = True
        self.socket.close()
        if self.process:
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)


class Negotiator:
    def __init__(self, worker, resource, business=False):
        self.worker, self.resource = worker, resource
        self.channel = worker.call(dict(op='open', business=business))['channel']
        self.complete = False
        self.closed = False

    def respond(self, frame):
        result = self.worker.call(dict(op='nearby', channel=self.channel,
            kind=frame.kind, flags=frame.flags, payload=frame.payload.hex()))
        self.complete = result['complete']
        self.resource.credentials_sent = result['credentials_sent']
        self.resource.pending.extend((kind, bytes.fromhex(data)) for kind, data in result['pending'])
        return bytes.fromhex(result['reply']) if result['reply'] is not None else None

    def close(self):
        if not self.closed:
            self.closed = True
            self.worker.call(dict(op='close-channel', channel=self.channel))


class AuthSession:
    def __init__(self, worker):
        self.worker = worker
        self.generation = worker.call(dict(op='auth-open'))['generation']
        worker.auth_generation = self.generation
        self.backend = self  # Preserve only the existing media adapter contract.
        self.session_key = None
        self.closed = False

    def receive(self, envelope):
        try:
            result = self.worker.call(dict(op='auth', generation=self.generation,
                envelope=json.dumps(envelope, separators=(',', ':'), ensure_ascii=False)))
        except (ValueError, RuntimeError, OSError) as error:
            self.session_key = None
            raise AuthError('Rust business authentication failed: ' + str(error)) from error
        key = result.get('key')
        self.session_key = bytes.fromhex(key) if key else self.session_key
        metadata = result['metadata']
        return (bytes.fromhex(result['reply']) if result.get('reply') is not None else None,
                metadata)

    def close(self):
        self.session_key = None
        if self.worker.auth_generation == self.generation:
            self.worker.auth_generation = None
        if not self.closed:
            self.closed = True
            try:
                self.worker.call(dict(op='auth-close', generation=self.generation))
            except (ValueError, RuntimeError, OSError):
                pass  # A dead child has already dropped the native session.


class HiSightSession:
    """Low-volume RTSP IPC only; compressed video never crosses this channel."""
    def __init__(self, worker, generation):
        self.worker = worker
        self.closed = False
        self.pending = []
        self.on_plaintext = None
        self.encrypted = False
        self.media_endpoint = self.input_endpoint = self.setup_sequence = None
        self.peer_teardown = self.teardown_acknowledged = False
        ready = worker.call(dict(op='hisight-open', generation=generation))
        self.session = ready['session']
        self.initial_record = bytes.fromhex(ready['initial'])

    def initial(self):
        return self.initial_record

    def update(self, result):
        for name, value in result['state'].items():
            setattr(self, name, value)
        self.pending.extend(bytes.fromhex(p) for p in result['pending'])
        plaintexts = [bytes.fromhex(p) for p in result['plaintexts']]
        if self.on_plaintext:
            for payload in plaintexts:
                self.on_plaintext(payload)
        return result['events'], plaintexts

    def receive(self, data):
        return self.update(self.worker.call(dict(op='hisight-receive', session=self.session,
            data=data.hex(), capture=self.on_plaintext is not None)))

    def request(self, method, headers=None):
        if method != 'PLAY':
            raise ProtocolError('unsupported Rust HiSight adapter request')
        self.update(self.worker.call(dict(op='hisight-play', session=self.session)))

    def teardown(self):
        result = self.worker.call(dict(op='hisight-teardown', session=self.session))
        self.update(result)
        return bytes.fromhex(result['teardown']) if result['teardown'] else None

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                self.worker.call(dict(op='hisight-close', session=self.session))
            except (ValueError, RuntimeError, OSError):
                pass


class ControlSpeaker:
    def __init__(self, owner):
        self.owner = owner
        self.values = {}

    @property
    def ports(self):
        value = self.values.get('ports')
        return tuple(value) if value else None

    @ports.setter
    def ports(self, value):
        self.owner.update(self.owner.command('dmsdp-ports', ports=list(value)))

    def __getattr__(self, name):
        if name in ('session_id', 'sequence', 'setup_sequence', 'format', 'ready'):
            return self.values.get(name)
        raise AttributeError(name)


class ControlSession:
    """DMSDP control state lives in the authenticated private Rust worker."""
    def __init__(self, worker, generation, key, device_info, audio=False):
        from cipher import Cipher
        self.worker = worker
        self.device_info = device_info
        self.cipher = Cipher(key)  # Transitional media/clock adapter key only.
        self.on_plaintext = None
        self.pending = []
        self.closed = False
        self.speaker = ControlSpeaker(self) if audio else None
        try:
            ready = worker.call(dict(op='dmsdp-open', generation=generation,
                device_info=device_info, audio=audio))
            self.session = ready['session']
            self.initial_record = bytes.fromhex(ready['initial'])
            self.update(dict(ready, events=[], pending=[], plaintexts=[]))
        except BaseException:
            self.cipher.close()
            raise

    def command(self, op, **fields):
        return self.worker.call(dict(op=op, session=self.session, **fields))

    def update(self, result):
        for name, value in result['state'].items():
            if name == 'speaker':
                if self.speaker is not None:
                    self.speaker.values = value or {}
            else:
                setattr(self, name, tuple(value) if name == 'clock' and value else value)
        self.pending.extend(bytes.fromhex(p) for p in result['pending'])
        if self.on_plaintext:
            for payload in result['plaintexts']:
                self.on_plaintext(bytes.fromhex(payload))
        return result['events']

    def initial(self):
        return self.initial_record

    def receive(self, data):
        return self.update(self.command('dmsdp-receive', data=data.hex(),
            now_us=time.monotonic_ns() // 1000, capture=self.on_plaintext is not None))

    def heartbeat(self):
        result = self.command('dmsdp-heartbeat')
        self.update(result)
        return bytes.fromhex(result['heartbeat'])

    def take_pending(self):
        pending, self.pending = self.pending, []
        return pending

    def stop_audio(self):
        self.update(self.command('dmsdp-stop-audio'))

    def close(self):
        if not self.closed:
            self.closed = True
            self.cipher.close()
            try:
                self.command('dmsdp-close')
            except (ValueError, RuntimeError, OSError):
                pass
