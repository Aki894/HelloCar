"""HiCar JSON business stream with optional native HiChain authentication."""
import codecs
import json

MAX_MESSAGE = 65536


class AuthError(ValueError):
    pass


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise AuthError('duplicate JSON field')
        obj[key] = value
    return obj


def parse_json(text):
    try:
        return json.loads(text, object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(AuthError('invalid JSON constant')))
    except (ValueError, RecursionError) as error:
        raise AuthError('invalid JSON message') from error


class JsonStream:
    """Incremental UTF-8 object framing, including escaped braces and coalescing."""
    def __init__(self):
        self.utf8 = codecs.getincrementaldecoder('utf-8')()
        self.parts = []
        self.depth = 0
        self.quoted = self.escaped = False
        self.size = 0
        self.failed = False

    def feed(self, data):
        if self.failed:
            raise AuthError('JSON stream requires reset')
        result = []
        try:
            for char in self.utf8.decode(data):
                if not self.parts and char.isspace():
                    continue
                if not self.parts and char != '{':
                    raise AuthError('expected JSON object')
                self.parts.append(char)
                self.size += len(char.encode('utf-8'))
                if self.size > MAX_MESSAGE:
                    raise AuthError('JSON message exceeds size limit')
                if self.quoted:
                    if self.escaped:
                        self.escaped = False
                    elif char == '\\':
                        self.escaped = True
                    elif char == '"':
                        self.quoted = False
                elif char == '"':
                    self.quoted = True
                elif char in '{[':
                    self.depth += 1
                    if self.depth > 32:
                        raise AuthError('JSON nesting exceeds limit')
                elif char in '}]':
                    self.depth -= 1
                    if self.depth == 0:
                        result.append(parse_json(''.join(self.parts)))
                        self.parts.clear()
                        self.size = 0
        except (AuthError, UnicodeError) as error:
            self.failed = True
            self.parts.clear()
            raise AuthError('invalid JSON business stream') from error
        return result

    def finish(self):
        try:
            self.utf8.decode(b'', final=True)
        except UnicodeError as error:
            raise AuthError('incomplete UTF-8 business stream') from error
        if self.parts:
            raise AuthError('incomplete JSON business stream')


class AuthSession:
    def __init__(self, identity, model, backend_factory=None):
        self.identity = identity
        self.model = model
        self.peer_id = None
        self.backend_factory = backend_factory
        self.backend = None

    def receive(self, envelope):
        if not isinstance(envelope, dict):
            raise AuthError('expected authentication envelope')
        operation = envelope.get('oper_type')
        if type(operation) is not int or operation not in (1, 3):
            raise AuthError('unsupported authentication operation')
        data = envelope.get('data')
        if not isinstance(data, str) or len(data.encode('utf-8')) > MAX_MESSAGE:
            raise AuthError('invalid authentication data')
        inner = parse_json(data)
        if not isinstance(inner, dict):
            raise AuthError('authentication data must be an object')
        if operation == 1:
            peer = inner.get('deviceId')
            if not isinstance(peer, str) or not 1 <= len(peer.encode('utf-8')) <= 64:
                raise AuthError('invalid peer identity length')
            if self.peer_id is not None:
                raise AuthError('repeated identity handshake')
            if inner.get('usb_connection', False) is not False:
                raise AuthError('wireless probe received a USB handshake')
            self.peer_id = peer
            if self.backend_factory:
                self.backend = self.backend_factory(self.identity.device_id, peer, self.identity.pin)
            details = dict(deviceId=self.identity.device_id, devicename=self.identity.name,
                           has_pin=True, usb_connection=False, CONNECT_ABILITY_KEY='1',
                           CAR_MODE_ID=self.model)
            reply = dict(version='A_0', discover_type=1, oper_type=1,
                         data=json.dumps(details, separators=(',', ':'), ensure_ascii=False),
                         usb_connection=False)
            return json.dumps(reply, separators=(',', ':'), ensure_ascii=False).encode('utf-8'), {
                'operation': 1, 'peer_id_bytes': len(peer.encode('utf-8')), 'pin_required': True}
        if self.peer_id is None:
            raise AuthError('authentication before identity handshake')
        # Report only non-secret protocol metadata for backend compatibility work.
        message = inner.get('message')
        if type(message) is not int or not 0 <= message <= 0xffffffff:
            message = None
        if self.backend is None:
            return None, dict(operation=3, message=message, backend='not_connected')
        code, packets = self.backend.receive(data.encode('utf-8'))
        if 1 in self.backend.results:
            raise AuthError('HiChain authentication failed')
        replies = []
        for packet in packets:
            # Validate native output before embedding it in the business envelope.
            parsed = parse_json(packet.decode('utf-8'))
            if not isinstance(parsed, dict):
                raise AuthError('invalid native authentication output')
            reply = dict(version='A_0', discover_type=1, oper_type=3,
                         data=packet.decode('utf-8'), usb_connection=False)
            replies.append(json.dumps(reply, separators=(',', ':')).encode('utf-8'))
        return b''.join(replies) or None, dict(operation=3, message=message,
                   backend='hichain', native_code=code, replies=len(replies),
                   results=list(self.backend.results), key_ready=self.backend.session_key is not None)

    def close(self):
        if self.backend:
            self.backend.close()
            self.backend = None
