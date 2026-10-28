"""Strict RTP/ADTS extraction for the observed HiCar AAC speaker stream."""
import struct
from nearby_wire import ProtocolError

RATES = (96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
         16000, 12000, 11025, 8000, 7350)


def adts_frames(data):
    frames = []
    offset = 0
    while offset < len(data):
        h = data[offset:offset+7]
        if len(h) < 7 or h[0] != 255 or h[1] & 0xf6 != 0xf0:
            raise ProtocolError('invalid ADTS header')
        rate_index = (h[2] >> 2) & 15
        channels = ((h[2] & 1) << 2) | (h[3] >> 6)
        length = ((h[3] & 3) << 11) | (h[4] << 3) | (h[5] >> 5)
        header_size = 7 if h[1] & 1 else 9
        if rate_index >= len(RATES) or channels not in (1, 2) or not header_size < length <= 8191:
            raise ProtocolError('unsupported ADTS format')
        if offset + length > len(data):
            raise ProtocolError('incomplete ADTS frame')
        frames.append((data[offset:offset+length], RATES[rate_index], channels,
                       1024*((h[6] & 3)+1)))
        offset += length
    if not frames:
        raise ProtocolError('empty AAC packet')
    return frames


def rtp_audio(packet):
    if len(packet) < 12 or packet[0] >> 6 != 2:
        raise ProtocolError('invalid audio RTP header')
    first, second, sequence, timestamp, stream = struct.unpack('!BBHII', packet[:12])
    if second & 127 != 96:
        raise ProtocolError('unsupported audio RTP payload type')
    offset = 12 + 4*(first & 15)
    if offset > len(packet):
        raise ProtocolError('truncated audio RTP CSRC')
    if first & 16:
        if offset+4 > len(packet):
            raise ProtocolError('truncated audio RTP extension')
        offset += 4+4*int.from_bytes(packet[offset+2:offset+4], 'big')
    end = len(packet)
    if first & 32:
        padding = packet[-1]
        if not padding or padding > end-offset:
            raise ProtocolError('invalid audio RTP padding')
        end -= padding
    if offset >= end:
        raise ProtocolError('empty audio RTP payload')
    return sequence, timestamp, stream, adts_frames(packet[offset:end])


class Audio:
    """Track independent SSRCs with a bounded reorder window; no media history."""
    def __init__(self):
        self.streams = {}
        self.packets = self.frames = self.samples = self.lost = self.duplicates = 0

    def receive(self, packet):
        sequence, timestamp, stream, frames = rtp_audio(packet)
        # DMSDP packs usage metadata into the upper SSRC bits. Its native
        # OnRTPData masks with 0xfff before looking up the sequence/reorder
        # state. Treating usage changes as new sources invents packet loss.
        stream &= 0xfff
        if stream not in self.streams:
            if len(self.streams) >= 8:
                raise ProtocolError('too many audio streams')
            self.streams[stream] = dict(expected=sequence, pending={}, timestamp=None,
                                        sample_offset=0, rate=None)
        state = self.streams[stream]
        distance = (sequence-state['expected']) & 65535
        if distance >= 32768 or sequence in state['pending']:
            self.duplicates += 1
            return []
        if distance > 16:
            self.lost += distance
            state['expected'] = sequence
            state['pending'].clear()
        state['pending'][sequence] = (timestamp, frames)
        if len(state['pending']) >= 8 and state['expected'] not in state['pending']:
            nearest = min(state['pending'], key=lambda s: (s-state['expected']) & 65535)
            self.lost += (nearest-state['expected']) & 65535
            state['expected'] = nearest
        output = []
        while state['expected'] in state['pending']:
            stamp, ready = state['pending'].pop(state['expected'])
            self.packets += 1
            for frame, rate, channels, samples in ready:
                if state['timestamp'] != stamp or state['rate'] != rate:
                    state.update(timestamp=stamp, rate=rate, sample_offset=0)
                output.append(dict(data=frame, rate=rate, channels=channels, samples=samples,
                                   rtp_timestamp=stamp, stream=stream,
                                   timestamp_offset_samples=state['sample_offset']))
                state['sample_offset'] += samples
                self.frames += 1
                self.samples += samples
            state['expected'] = (state['expected']+1) & 65535
        return output
