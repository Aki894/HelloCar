"""Independently implemented Nearby control framing from observed interfaces.

Frame: 7f | kind varint | flags TLV | payload length varint | payload | CRC16-ARC LE.
Unlike protobuf, bit 7 marks the LAST byte of each little-endian base-128 integer.
Encrypted payloads are preserved, not decrypted or treated as plaintext.
"""
from dataclasses import dataclass

MAX_VALUE = (1 << 28) - 1
MAX_PAYLOAD = 65536
MAX_OPTIONS = 256
MAX_BUFFER = MAX_PAYLOAD + MAX_OPTIONS + 32


class ProtocolError(ValueError):
    pass


class Incomplete(Exception):
    pass


def pack_uint(value):
    if not 0 <= value <= MAX_VALUE:
        raise ProtocolError('integer outside 28-bit range')
    result = bytearray()
    while value >= 128:
        result.append(value & 127)
        value >>= 7
    result.append(value | 128)
    return bytes(result)


def read_uint(data, offset=0):
    value = 0
    for shift in range(0, 28, 7):
        if offset >= len(data):
            raise Incomplete()
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte & 128:
            return value, offset
    raise ProtocolError('unterminated 28-bit integer')


def crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def pack_tlv(tag, value):
    return pack_uint(tag) + pack_uint(len(value)) + value


def read_tlvs(data, max_value=MAX_PAYLOAD):
    result = []
    offset = 0
    try:
        while offset < len(data):
            tag, offset = read_uint(data, offset)
            size, offset = read_uint(data, offset)
            if size > max_value:
                raise ProtocolError('TLV length exceeds limit')
            if offset + size > len(data):
                raise ProtocolError('truncated TLV value')
            result.append((tag, bytes(data[offset:offset + size])))
            offset += size
    except Incomplete as error:
        raise ProtocolError('truncated TLV header') from error
    return result


@dataclass(frozen=True)
class Frame:
    kind: int
    flags: int
    options: bytes
    payload: bytes

    @property
    def encrypted(self):
        return bool(self.flags & 1)


def pack_frame(kind, payload, flags=0, options=b''):
    if len(payload) > MAX_PAYLOAD or len(options) > MAX_OPTIONS:
        raise ProtocolError('frame exceeds limit')
    header = b'\x7f' + pack_uint(kind) + pack_tlv(flags, options) + pack_uint(len(payload))
    body = header + payload
    return body + crc16(body).to_bytes(2, 'little')


class Decoder:
    """Fail closed on corruption; do not guess a new boundary inside payload."""
    def __init__(self):
        self.buffer = bytearray()
        self.failed = False

    def _take(self):
        data = self.buffer
        if not data:
            raise Incomplete()
        if data[0] != 0x7f:
            raise ProtocolError('unexpected frame marker')
        kind, offset = read_uint(data, 1)
        flags, offset = read_uint(data, offset)
        size, offset = read_uint(data, offset)
        if size > MAX_OPTIONS:
            raise ProtocolError('option length exceeds limit')
        if len(data) < offset + size:
            raise Incomplete()
        options = bytes(data[offset:offset + size])
        offset += size
        length, offset = read_uint(data, offset)
        if length > MAX_PAYLOAD:
            raise ProtocolError('payload length exceeds limit')
        end = offset + length
        if len(data) < end + 2:
            raise Incomplete()
        if crc16(data[:end]) != int.from_bytes(data[end:end + 2], 'little'):
            raise ProtocolError('CRC mismatch')
        frame = Frame(kind, flags, options, bytes(data[offset:end]))
        del data[:end + 2]
        return frame

    def feed(self, chunk):
        if self.failed:
            raise ProtocolError('decoder must be reset after corruption')
        frames = []
        try:
            # Process large coalesced reads without retaining an unbounded buffer.
            for start in range(0, len(chunk), 4096):
                self.buffer.extend(chunk[start:start + 4096])
                while self.buffer:
                    try:
                        frames.append(self._take())
                    except Incomplete:
                        break
                if len(self.buffer) > MAX_BUFFER:
                    raise ProtocolError('receive buffer exceeds limit')
        except ProtocolError:
            self.buffer.clear()
            self.failed = True
            raise
        return frames

    def finish(self):
        if self.buffer:
            raise ProtocolError('stream ended inside frame')
