"""DMSDP Nearby module framing and the observed control-port negotiation.

Unlike CCMP, this framing has no flags/options TLV. A zeroed 16-byte module-1
request asks the sink to create a control server. Successful response contains
status 0, a two-byte network-order port, and 13 reserved zero bytes.
"""
from dataclasses import dataclass
from nearby_wire import Incomplete, ProtocolError, crc16, pack_uint, read_uint

MAX_PAYLOAD = 65536


@dataclass(frozen=True)
class Packet:
    module: int
    payload: bytes


def pack(module, payload):
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError('DMSDP packet exceeds limit')
    raw = b'\x7f' + pack_uint(module) + pack_uint(len(payload)) + payload
    return raw + crc16(raw).to_bytes(2, 'little')


class Decoder:
    def __init__(self):
        self.buffer = bytearray()
        self.failed = False

    def feed(self, data):
        if self.failed:
            raise ProtocolError('DMSDP decoder requires reset')
        packets = []
        self.buffer.extend(data)
        try:
            while self.buffer:
                if self.buffer[0] != 0x7f:
                    raise ProtocolError('invalid DMSDP frame marker')
                try:
                    module, offset = read_uint(self.buffer, 1)
                    size, offset = read_uint(self.buffer, offset)
                except Incomplete:
                    break
                if size > MAX_PAYLOAD:
                    raise ProtocolError('DMSDP payload exceeds limit')
                end = offset + size
                if len(self.buffer) < end + 2:
                    break
                if crc16(self.buffer[:end]) != int.from_bytes(self.buffer[end:end + 2], 'little'):
                    raise ProtocolError('DMSDP checksum mismatch')
                packets.append(Packet(module, bytes(self.buffer[offset:end])))
                del self.buffer[:end + 2]
            if len(self.buffer) > MAX_PAYLOAD + 11:
                raise ProtocolError('DMSDP buffer exceeds limit')
        except ProtocolError:
            self.failed = True
            self.buffer.clear()
            raise
        return packets

    def finish(self):
        if self.buffer:
            raise ProtocolError('incomplete DMSDP packet')


class Negotiation:
    def __init__(self, ready_control_port):
        if not 1024 <= ready_control_port <= 65535:
            raise ValueError('invalid ready control port')
        self.port = ready_control_port
        self.complete = False
        self.requests = 0

    def respond(self, packet):
        if packet.module != 1 or packet.payload != bytes(16) or self.requests >= 3:
            raise ProtocolError('unsupported DMSDP negotiation packet')
        self.requests += 1
        self.complete = True
        return pack(1, b'\x00' + self.port.to_bytes(2, 'big') + bytes(13))
