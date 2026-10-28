"""Bounded Nearby ResourceManager and software-AP credential negotiation."""
import re
from nearby_wire import Incomplete, ProtocolError, pack_tlv, pack_uint, read_tlvs, read_uint

CHANNELS = (36, 40, 44, 48, 149, 153, 157, 161, 165)


def abilities(data):
    """Detailed ability uses key/value integers; key 5 is a channel bitset."""
    if len(data) > 256:
        raise ProtocolError('P2P capability exceeds limit')
    fields, offset = {}, 0
    try:
        while offset < len(data):
            tag, offset = read_uint(data, offset)
            if tag in fields or len(fields) >= 32:
                raise ProtocolError('invalid P2P capability fields')
            value, offset = read_uint(data, offset)
            fields[tag] = value
    except Incomplete as error:
        raise ProtocolError('truncated P2P capability') from error
    return fields


class Resource:
    def __init__(self, offer):
        self.offer = offer
        self.authenticated = False
        self.session_key = None
        self.negotiated = False
        self.credentials_sent = False
        self.pending = []
        self.data_port = None

    def take_pending(self):
        pending, self.pending = self.pending, []
        return pending

    def respond(self, frame):
        if not self.authenticated or frame.encrypted:
            return None
        replies = []
        for tag, value in read_tlvs(frame.payload):
            if frame.kind == 4 and tag == 1:
                try:
                    channel, offset = read_uint(value)
                except Incomplete as error:
                    raise ProtocolError('missing data channel') from error
                detailed = read_tlvs(value[offset:])
                if channel != 3 or len(detailed) != 1 or detailed[0][0] != 3:
                    raise ProtocolError('unsupported network negotiation')
                caps = abilities(detailed[0][1])
                # The actual ready AP is 5 GHz channel 149, and the phone must
                # support the client role. No unimplemented mode is advertised.
                channels = caps.get(5, 0)
                accepted = caps.get(2) == 1 and caps.get(4) == 1 and bool(channels & (1 << 4))
                result = pack_uint(3) + pack_uint(1 if accepted else 255)
                if accepted:
                    result += pack_tlv(3, b'\x01' + pack_uint(self.offer.frequency))
                replies.append(pack_tlv(2, result))
                self.negotiated = accepted
            elif frame.kind == 4 and tag == 3:
                if not self.negotiated or self.data_port is None:
                    raise ProtocolError('DMSDP endpoint not ready')
                try:
                    channel, offset = read_uint(value)
                    business, offset = read_uint(value, offset)
                    size, offset = read_uint(value, offset)
                    if size > 128 or offset + size > len(value):
                        raise ProtocolError('invalid DMSDP tag length')
                    value[offset:offset + size].decode('utf-8')
                    offset += size
                    protocol, offset = read_uint(value, offset)
                except (Incomplete, UnicodeError) as error:
                    raise ProtocolError('invalid DMSDP socket request') from error
                if (channel, business, protocol) != (3, 20, 1) or offset != len(value):
                    raise ProtocolError('unsupported data socket request')
                replies.append(pack_tlv(4, pack_uint(0) + pack_uint(self.data_port) + value))
            elif frame.kind == 4 and tag == 7:
                try:
                    channel, offset = read_uint(value)
                    status, offset = read_uint(value, offset)
                    selected = read_tlvs(value[offset:])
                    if not (self.negotiated and channel == 3 and status == 1
                            and len(selected) == 1 and selected[0][0] == 3):
                        raise ProtocolError('invalid network selection result')
                    role = selected[0][1]
                    frequency, end = read_uint(role, 1)
                    if role[0] != 2 or end != len(role) or frequency != self.offer.frequency:
                        raise ProtocolError('peer selected unsupported network role')
                except (Incomplete, IndexError) as error:
                    raise ProtocolError('truncated network selection result') from error
                if len(self.pending) >= 4:
                    raise ProtocolError('too many pending network commands')
                # Result says the phone is GC. GO initiates GET_GC_MAC before
                # transmitting credentials, on protocol 33 rather than 4.
                self.pending.append((33, pack_tlv(1, b'')))
            elif frame.kind == 33 and tag in (1, 2, 4):
                if not self.negotiated:
                    raise ProtocolError('network command before negotiation')
                if tag in (2, 4):
                    try:
                        address = value.decode('ascii')
                    except UnicodeError as error:
                        raise ProtocolError('invalid client address') from error
                    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', address):
                        raise ProtocolError('invalid client address')
                    replies.append(pack_tlv(3, self.offer.credentials()))
                    self.credentials_sent = True
                else:
                    # Request for client MAC is the opposite role; do not pretend
                    # this AP can join another group in the same test window.
                    replies.append(pack_tlv(2, b'busy'))
            elif frame.kind == 33 and tag == 5:
                replies.append(pack_tlv(6, b''))
        return b''.join(replies) or None
