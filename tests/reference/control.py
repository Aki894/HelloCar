"""Limited responder for the first Nearby channel-management exchange.

Advertises plaintext control framing; HiChain application authentication is separate.
Business socket offers are separate from PIN and authentication-success responses.
"""
import uuid
from nearby_wire import Incomplete, ProtocolError, pack_tlv, pack_uint, read_tlvs, read_uint

FE36 = '0000fe36-0000-1000-8000-00805f9b34fb'


class Negotiator:
    def __init__(self, summary, business_channel=None, resource=None):
        if not 1 <= len(summary) <= 256:
            raise ValueError('local summary length must be 1..256 bytes')
        self.summary = summary
        self.seen = set()
        self.business_channel = business_channel
        self.resource = resource

    def business_response(self, frame):
        if not self.complete or self.business_channel is None:
            return None
        responses = []
        for tag, value in read_tlvs(frame.payload):
            if tag != 3:
                continue
            try:
                channel, offset = read_uint(value)
                business, offset = read_uint(value, offset)
                length, offset = read_uint(value, offset)
                if length > 128 or offset + length > len(value):
                    raise ProtocolError('invalid business tag length')
                value[offset:offset + length].decode('utf-8')
                offset += length
                protocol, offset = read_uint(value, offset)
            except (Incomplete, UnicodeDecodeError) as error:
                raise ProtocolError('invalid business request') from error
            # Only the observed BR stream request for HiCar business 19 is supported.
            if channel != 2 or business != 19 or protocol != 0 or offset != len(value):
                raise ProtocolError('unsupported business request')
            endpoint = pack_uint(16) + uuid.UUID(FE36).bytes
            result = pack_uint(0) + pack_uint(self.business_channel) + value + endpoint
            responses.append(pack_tlv(4, result))
        return b''.join(responses) if responses else None

    def respond(self, frame):
        if frame.encrypted:
            return None
        if frame.kind in (4, 33) and self.resource and self.complete:
            return self.resource.respond(frame)
        if frame.kind == 2:
            return self.business_response(frame)
        if frame.kind != 0:
            return None
        fields = read_tlvs(frame.payload)
        seen = set(self.seen)
        replies = []
        for tag, value in fields:
            if tag == 1:
                if len(value) != 1 or value[0] < 2:
                    raise ProtocolError('unsupported CCMP version')
                replies.append(pack_tlv(2, b'\x02'))
                seen.add('version')
            elif tag == 3:
                if not 1 <= len(value) <= 256:
                    raise ProtocolError('invalid peer summary length')
                replies.append(pack_tlv(4, self.summary))
                seen.add('summary')
            elif tag == 5:
                if value not in (b'\x00', b'\x01', b'\x02'):
                    raise ProtocolError('invalid framing encryption preference')
                replies.append(pack_tlv(6, b'\x00'))
                seen.add('framing')
        self.seen = seen
        return b''.join(replies) if replies else None

    @property
    def complete(self):
        return self.seen == {'version', 'summary', 'framing'}
