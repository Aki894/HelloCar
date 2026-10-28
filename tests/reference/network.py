"""Frozen pure network-offer reference; no service or network mutations."""
from dataclasses import dataclass, field
import ipaddress
import re


@dataclass(frozen=True)
class Offer:
    ssid: str = field(repr=False)
    bssid: str = field(repr=False)
    password: str = field(repr=False)
    owner_ip: str = '192.168.49.1'
    client_ip: str = '192.168.49.2'
    frequency: int = 5745
    port: int = 4005

    def __post_init__(self):
        for text in (self.ssid, self.password):
            if not text.isascii() or any(c in text for c in ('\n', '\r', '#', '\x00')):
                raise ValueError('invalid network text field')
        if not 1 <= len(self.ssid) <= 32 or not 8 <= len(self.password) <= 63:
            raise ValueError('invalid SSID or password length')
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', self.bssid):
            raise ValueError('invalid AP address')
        owner, client = ipaddress.IPv4Address(self.owner_ip), ipaddress.IPv4Address(self.client_ip)
        if (owner == client or owner not in ipaddress.IPv4Network('192.168.49.0/24')
                or client not in ipaddress.IPv4Network('192.168.49.0/24')):
            raise ValueError('invalid test network addresses')
        if self.frequency != 5745 or not 1024 <= self.port <= 65535:
            raise ValueError('unsupported test network endpoint')

    def credentials(self):
        # Reference software-AP path: client address, four Wi-Fi fields plus AP
        # marker, protocol version, control port, AP mode and actual gateway.
        config = '\n'.join((self.ssid, self.bssid, self.password, str(self.frequency), '1'))
        return (f'{self.client_ip}##{config}##version:3##{self.port}##2'
                f'##hicarApIp:{self.owner_ip}').encode('ascii')
