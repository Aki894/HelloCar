"""Experimental DMSDP control framing and plaintext capability exchange.

AES is offered only with an authenticated session key. Unsupported encrypted
frames are preserved for private analysis, never decoded as plaintext.
"""
from dataclasses import dataclass, field
import re
import json
import time
from nearby_wire import ProtocolError, read_uint, pack_uint, Incomplete
from cipher import Cipher
from audio_wire import Speaker

MAX_FRAME = 1498
MAX_BODY = 65536


@dataclass(frozen=True)
class ControlFrame:
    marker: int
    payload: bytes = field(repr=False)


def pack_frame(payload, marker=0):
    if marker not in (0, 0xab) or not 0 < len(payload) < MAX_FRAME:
        raise ProtocolError('invalid DMSDP control frame')
    return bytes([marker]) + len(payload).to_bytes(2, 'big') + payload


class Decoder:
    def __init__(self):
        self.buffer = bytearray()
        self.failed = False

    def feed(self, data):
        if self.failed:
            raise ProtocolError('control decoder requires reset')
        self.buffer.extend(data)
        frames = []
        try:
            while len(self.buffer) >= 3:
                marker, size = self.buffer[0], int.from_bytes(self.buffer[1:3], 'big')
                if marker not in (0, 0xab) or not 0 < size < MAX_FRAME:
                    raise ProtocolError('invalid control frame header')
                if len(self.buffer) < size + 3:
                    break
                frames.append(ControlFrame(marker, bytes(self.buffer[3:3 + size])))
                del self.buffer[:3 + size]
            if len(self.buffer) > MAX_FRAME + 2:
                raise ProtocolError('control buffer exceeds limit')
        except ProtocolError:
            self.failed = True
            self.buffer.clear()
            raise
        return frames

    def finish(self):
        if self.buffer:
            raise ProtocolError('incomplete control frame')


@dataclass(frozen=True)
class Message:
    start: str
    headers: dict = field(repr=False)
    body: bytes = field(default=b'', repr=False)

    def metadata(self):
        # Field names and a few numeric capabilities only. Device identity,
        # encrypted keys, nonces and body contents never enter normal logs.
        info = dict(method=self.start.split(' ', 1)[0], header_names=sorted(self.headers),
                    body_bytes=len(self.body))
        for name in ('cseq', 'cryptover', 'cryptoability', 'cryptoswitch', 'udpka', 'lowdelay'):
            value = self.headers.get(name)
            if value is not None and re.fullmatch(r'[0-9]{1,9}', value):
                info[name] = int(value)
        return info


def encode(start, headers):
    if start not in ('OPTIONS * DMSDP/1.0', 'GET_PARAMETER * DMSDP/1.0', 'SETUP * DMSDP/1.0',
                     'PLAY * DMSDP/1.0', 'TEARDOWN * DMSDP/1.0', 'DMSDP/1.0 200 OK'):
        raise ProtocolError('unsupported initial control request')
    rows = [start]
    for name, value in headers.items():
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,63}', name):
            raise ProtocolError('invalid control header name')
        value = str(value)
        if not value.isascii() or any(c in value for c in ('\r', '\n', '\x00')):
            raise ProtocolError('invalid control header value')
        rows.append(name + ': ' + value)
    return ('\r\n'.join(rows) + '\r\n\r\n').encode('ascii')


class Messages:
    """Text messages can span transport frames; reject duplicate/ambiguous fields."""
    def __init__(self, protocol='DMSDP'):
        if protocol not in ('DMSDP', 'RTSP'):
            raise ValueError('invalid control protocol')
        self.protocol = protocol
        self.buffer = bytearray()
        self.failed = False

    def feed(self, payload):
        if self.failed:
            raise ProtocolError('control messages require reset')
        self.buffer.extend(payload)
        messages = []
        try:
            while self.buffer:
                end = self.buffer.find(b'\r\n\r\n')
                if end < 0:
                    if len(self.buffer) > 8192:
                        raise ProtocolError('control header exceeds limit')
                    break
                if end > 8192:
                    raise ProtocolError('control header exceeds limit')
                try:
                    rows = bytes(self.buffer[:end]).decode('ascii').split('\r\n')
                except UnicodeError as error:
                    raise ProtocolError('non-text control message') from error
                if not (re.fullmatch(r'[A-Z_]+ \S+ ' + self.protocol + r'/1\.0', rows[0])
                        or re.fullmatch(self.protocol + r'/1\.0 [1-5][0-9]{2}(?: [ -~]+)?', rows[0])):
                    raise ProtocolError('unsupported control start line')
                headers = {}
                for row in rows[1:]:
                    name, sep, value = row.partition(':')
                    if not sep or not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,63}', name):
                        raise ProtocolError('invalid control header')
                    name = name.lower()
                    if name in headers or len(headers) >= 64:
                        raise ProtocolError('duplicate or excess control headers')
                    headers[name] = value.strip()
                length = headers.get('content-length', '0')
                if not re.fullmatch(r'[0-9]{1,5}', length) or int(length) > MAX_BODY:
                    raise ProtocolError('invalid control body length')
                total = end + 4 + int(length)
                if len(self.buffer) < total:
                    break
                messages.append(Message(rows[0], headers, bytes(self.buffer[end + 4:total])))
                del self.buffer[:total]
            if len(self.buffer) > MAX_BODY + 8196:
                raise ProtocolError('control message buffer exceeds limit')
        except ProtocolError:
            self.failed = True
            self.buffer.clear()
            raise
        return messages


class Session:
    def __init__(self, session_key=None, device_info=None, audio=False):
        self.decoder = Decoder()
        self.messages = Messages()
        self.pending = []
        self.negotiated = False
        self.cipher = Cipher(session_key) if session_key else None
        self.on_plaintext = None
        self.device_info = device_info
        self.device_exchanged = False
        self.clock = None
        self.media_port = None
        self.audio = audio
        self.speaker = Speaker() if audio else None
        self.heartbeat_sequence = 1

    def heartbeat(self):
        if not self.negotiated:
            raise ProtocolError('heartbeat before control negotiation')
        self.heartbeat_sequence += 1
        payload = encode('GET_PARAMETER * DMSDP/1.0', {'CSeq': self.heartbeat_sequence})
        return (pack_frame(self.cipher.encrypt(payload), 0xab)
                if self.cipher else pack_frame(payload))

    def send_payload(self, payload):
        if not self.negotiated:
            raise ProtocolError('control session is not negotiated')
        self.pending.append(pack_frame(self.cipher.encrypt(payload), 0xab)
                            if self.cipher else pack_frame(payload))

    def send_business(self, module, data_type, body):
        payload = (b'$' + module.to_bytes(4, 'big') + data_type.to_bytes(4, 'big')
                   + len(body).to_bytes(2, 'big') + body)
        self.send_payload(payload)

    def initial(self):
        return pack_frame(encode('OPTIONS * DMSDP/1.0', {
            # The native peer compares this field with the protocol sentinel
            # 0xde. It is not a bit mask of implemented cipher algorithms.
            'CryptoVer': 1, 'CryptoAbility': 222,
            'CryptoAlg': 'aes128-ctr' if self.cipher else 'null',
            'UdpKA': 0, 'LowDelay': 0, 'CSeq': 1}))

    def receive(self, data):
        events = []
        for frame in self.decoder.feed(data):
            if frame.marker == 0xab:
                if not self.cipher:
                    events.append(dict(encrypted=True, size=len(frame.payload)))
                    continue
                if not self.negotiated:
                    raise ProtocolError('encrypted data before negotiation')
                payload = self.cipher.decrypt(frame.payload)
                if self.on_plaintext:
                    self.on_plaintext(payload)
            else:
                payload = frame.payload
            if payload.startswith(b'$'):
                # Native CtrlReadBinaryData: '$', u32 module, u32 type,
                # u16 body size, body. Keep bodies out of ordinary logs.
                if len(payload) < 11 or int.from_bytes(payload[9:11], 'big') != len(payload) - 11:
                    raise ProtocolError('invalid binary control message')
                events.append(dict(binary=True, module=int.from_bytes(payload[1:5], 'big'),
                                   data_type=int.from_bytes(payload[5:9], 'big'),
                                   body_bytes=len(payload) - 11))
                if payload[1:9] == b'\0\0\0\5\xff\xff\xff\xff':
                    try:
                        command, offset = read_uint(payload[11:])
                        port, end = read_uint(payload[11:], offset)
                    except Incomplete as error:
                        raise ProtocolError('incomplete HiSight endpoint') from error
                    if command != 101 or end != len(payload) - 11 or not 1 <= port <= 65535:
                        raise ProtocolError('invalid HiSight endpoint')
                    self.media_port = port
                    events.append(dict(hisight_endpoint=True, port=port))
                if payload[1:9] == b'\0\0\0\3\xff\xff\xff\xff' and self.device_info:
                    body = payload[11:]
                    try:
                        command, offset = read_uint(body)
                    except Incomplete as error:
                        raise ProtocolError('incomplete device command') from error
                    events.append(dict(device_command=command, body_bytes=len(body) - offset))
                    if command == 101:
                        try:
                            peer = json.loads(body[offset:])
                        except (ValueError, UnicodeError) as error:
                            raise ProtocolError('invalid peer device information') from error
                        if not isinstance(peer, dict) or not isinstance(peer.get('deviceId'), str):
                            raise ProtocolError('missing peer device information')
                        if not self.device_exchanged:
                            own = dict(self.device_info, businessId=peer.get('businessId', 1))
                            self.send_business(3, 0xffffffff, pack_uint(101) + json.dumps(
                                own, separators=(',', ':')).encode('utf-8'))
                            self.device_exchanged = True
                            events.append(dict(device_info_sent=True))
                    elif command == 104:
                        if not self.device_exchanged or len(body) - offset != 4:
                            raise ProtocolError('invalid service discovery request')
                        mask = int.from_bytes(body[offset:], 'big')
                        events.append(dict(service_request_mask=mask))
                        if mask & 8:
                            service = dict(deviceId=self.device_info['deviceId'],
                                           deviceName=self.device_info['deviceName'],
                                           serviceId='display1', serviceType=8,
                                           properties={'4001': 1.0, '1009': 800, '1010': 480},
                                           status={})
                            self.send_business(3, 0xffffffff, pack_uint(102) + json.dumps(
                                service, separators=(',', ':')).encode('utf-8'))
                            events.append(dict(service_announced=8))
                        if mask & 4 and self.audio:
                            service = dict(deviceId=self.device_info['deviceId'],
                                           deviceName=self.device_info['deviceName'],
                                           serviceId='speaker1', serviceType=4,
                                           properties={'2003': '48000,44100', '2004': '1',
                                                       '2005': '12'}, status={})
                            self.send_business(3, 0xffffffff, pack_uint(102) + json.dumps(
                                service, separators=(',', ':')).encode('utf-8'))
                            events.append(dict(service_announced=4))
            else:
                for message in self.messages.feed(payload):
                    events.append(message.metadata())
                    if self.speaker:
                        if message.headers.get('serviceid') == 'speaker1' and not self.negotiated:
                            raise ProtocolError('speaker before control negotiation')
                        audio_events = self.speaker.receive(message, encode)
                        if audio_events is not None:
                            events.extend(audio_events)
                            for reply in self.speaker.pending:
                                self.send_payload(reply)
                            self.speaker.pending.clear()
                            continue
                    if (message.start == 'SET_PARAMETER * DMSDP/1.0'
                            and 'cryptoswitch' in message.headers):
                        headers = message.headers
                        if ('cryptoswitch' not in headers or self.negotiated
                                or headers.get('cryptover') != '1'
                                or headers['cryptoswitch'] != '222'
                                or headers.get('cryptoalg') != ('aes128-ctr' if self.cipher else 'null')
                                or message.body):
                            raise ProtocolError('unsupported control negotiation')
                        cseq = headers.get('cseq', '')
                        if not re.fullmatch(r'[0-9]{1,9}', cseq):
                            raise ProtocolError('invalid negotiation sequence')
                        self.pending.append(pack_frame(encode('DMSDP/1.0 200 OK', {
                            'CSeq': cseq, 'CryptoVer': 1, 'CryptoSwitch': 222,
                            'CryptoAlg': headers['cryptoalg'], 'Platform': 0})))
                        self.negotiated = True
                        events.append(dict(negotiated=True, cipher=headers['cryptoalg']))
                    elif (message.start == 'GET_PARAMETER * DMSDP/1.0'
                          and self.negotiated and not message.body
                          and set(message.headers) == {'cseq'}):
                        cseq = message.headers['cseq']
                        if not re.fullmatch(r'[0-9]{1,9}', cseq):
                            raise ProtocolError('invalid keepalive sequence')
                        # DMSDP uses symmetric one-way heartbeats. Its native
                        # OnGetParameterRequest marks the peer alive and sends
                        # no response; RTSP HiSight has separate reply rules.
                        events.append(dict(keepalive_received=True))
                    elif (message.start == 'SET_PARAMETER * DMSDP/1.0' and self.negotiated
                          and {'timeserverport', 'timeushigh', 'timeuslow'} <= message.headers.keys()):
                        try:
                            high, low = (int(message.headers[k]) & 0xffffffff
                                         for k in ('timeushigh', 'timeuslow'))
                            port = int(message.headers['timeserverport'])
                            sequence = message.headers['cseq']
                            if not 1 <= port <= 65535 or not re.fullmatch(r'[0-9]{1,9}', sequence):
                                raise ValueError()
                        except (KeyError, ValueError) as error:
                            raise ProtocolError('invalid peer clock parameters') from error
                        self.clock = ((high << 32) | low, time.monotonic_ns() // 1000, port)
                        self.send_payload(encode('DMSDP/1.0 200 OK', {'CSeq': sequence}))
                        events.append(dict(clock_initialized=True))
        return events

    def take_pending(self):
        pending, self.pending = self.pending, []
        return pending

    def stop_audio(self):
        if self.speaker:
            record = self.speaker.teardown(encode)
            if record:
                self.send_payload(record)

    def close(self):
        if self.cipher:
            self.cipher.close()
