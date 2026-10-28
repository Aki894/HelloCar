"""Consumer-side framing for caller-supplied 16 kHz mono PCM16 microphone data."""
import struct


def microphone_record(generation, pcm, pts_us=0):
    if (type(generation) is not int or not 0 < generation < 1 << 64
            or type(pts_us) is not int or not 0 <= pts_us < 1 << 64
            or not isinstance(pcm, bytes) or not pcm or len(pcm) > 16384 or len(pcm) % 2):
        raise ValueError('invalid microphone generation, timestamp or PCM')
    payload = struct.pack('<Q', generation) + pcm
    return struct.pack('<IBBHQ', 12 + len(payload), 130, 0, 0, pts_us) + payload
