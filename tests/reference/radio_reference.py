"""Frozen discovery reference; no hardware or application daemon."""
import time
def log(*args, **kwargs): pass

def beacon(model, sequence=1):
    if len(model) != 8:
        raise ValueError('model must contain exactly eight hex characters')
    raw = bytes.fromhex(model)
    if len(raw) != 4:
        raise ValueError('model must contain exactly four bytes')
    if not 0 <= sequence <= 255:
        raise ValueError('sequence must be between 0 and 255')
    return bytes([1, 1, 1, 3]) + raw[:3] + bytes([4, raw[3], 16, sequence])

def normalize_peer(value):
    """Strict stable Bluetooth address; whitespace is never hexadecimal input."""
    if not isinstance(value, str):
        raise ValueError('peer must be a six-byte colon-separated Bluetooth address')
    parts = value.split(':')
    if len(parts) != 6 or any((len(part) != 2 for part in parts)) or any((char not in '0123456789abcdefABCDEF' for part in parts for char in part)):
        raise ValueError('peer must be a six-byte colon-separated hexadecimal Bluetooth address')
    return ':'.join(parts).upper()

class PeerSelection:
    """One transport peer per explicitly bounded enrollment attempt.

    Agent requests can validate candidates but cannot select one. Only an actual
    FE35/FE36 socket takes the selection, shared by both profiles and the agent.
    HiChain still authenticates the selected phone before any network offer.
    """

    def __init__(self, adapter, selected=None, pair_seconds=0, clock=None, exclude_peers=()):
        if pair_seconds and (not 5 <= pair_seconds <= 120):
            raise ValueError('pairing window must be 5..120 seconds')
        if len(exclude_peers) > 8:
            raise ValueError('at most eight excluded peers are supported')
        self.excluded = frozenset((normalize_peer(peer) for peer in exclude_peers))
        self.prefix = adapter + '/dev_'
        self.selected = selected
        self.clock = clock or time.monotonic
        self.deadline = self.clock() + pair_seconds if pair_seconds else None
        if selected is not None and self.address(selected) is None:
            raise ValueError('selected phone must belong to the configured adapter')

    def address(self, device):
        if not isinstance(device, str) or not device.startswith(self.prefix):
            return None
        parts = device[len(self.prefix):].split('_')
        if len(parts) != 6 or any((len(part) != 2 for part in parts)):
            return None
        if any((char not in '0123456789abcdefABCDEF' for part in parts for char in part)):
            return None
        return ':'.join(parts).upper()

    def allows(self, device, select=False):
        address = self.address(device)
        if address is None:
            return False
        if self.selected is not None:
            return device == self.selected
        if address in self.excluded:
            return False
        if self.deadline is None or self.clock() >= self.deadline:
            return False
        if select:
            self.selected = device
            log('target_selected', address=address)
        return True
