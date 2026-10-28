"""Small encrypted HiSight UIBC sender and private local test socket."""
import asyncio
import json
import os
from pathlib import Path
import stat
import struct
import time
from cipher import Cipher
from nearby_wire import ProtocolError


KEYS = {'up': 19, 'down': 20, 'left': 21, 'right': 22, 'enter': 23,
        'back': 4, 'home': 3, 'play_pause': 85}


class Input:
    def __init__(self, key):
        self.cipher = Cipher(key)
        self.start = time.monotonic()

    def pack(self, body):
        # UIBC has a four-byte clear header. The six reserved bytes and
        # event body are encrypted with a new IV, as in HiSight CTR records.
        data = self.cipher.encrypt(bytes([255]) * 6 + body)
        return b'\0\0' + (len(data) + 4).to_bytes(2, 'big') + data

    def key(self, name, down):
        if not isinstance(name, str) or name not in KEYS or type(down) is not bool:
            raise ProtocolError('unsupported input key')
        return self.pack(struct.pack('>BHBHHI', 3 if down else 4, 9, 0,
                                     KEYS[name], 0, 0))

    def touch(self, x, y, down, move=False):
        if type(x) is not int or type(y) is not int or not 0 <= x < 800 or not 0 <= y < 480:
            raise ProtocolError('input coordinate outside negotiated display')
        if type(down) is not bool or type(move) is not bool or move and not down:
            raise ProtocolError('invalid touch action')
        elapsed = int((time.monotonic() - self.start) * 1000) & 0xffffffff
        return self.pack(struct.pack('>BHBBHHIB', 2 if move else 0 if down else 1, 11, 1,
                                     0, x, y, elapsed, 0))


async def serve(writer, key, directory, log):
    """Root-private Unix socket, available only during a capture experiment."""
    root = Path(directory)
    if stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise ProtocolError('input directory must be private')
    path = root / 'hisight-input.sock'
    if path.exists():
        raise ProtocolError('input socket already exists')
    encoder = Input(key)
    lock = asyncio.Lock()
    async def command(reader, client):
        try:
            data = await asyncio.wait_for(reader.readline(), 2)
            if len(data) > 256:
                raise ProtocolError('input command too long')
            item = json.loads(data)
            if not isinstance(item, dict):
                raise ProtocolError('invalid input command')
            if set(item) == {'key'}:
                packets = [encoder.key(item['key'], True), encoder.key(item['key'], False)]
            elif set(item) == {'x', 'y'}:
                packets = [encoder.touch(item['x'], item['y'], True),
                           encoder.touch(item['x'], item['y'], False)]
            else:
                raise ProtocolError('unsupported input command')
            async with lock:
                for packet in packets:
                    writer.write(packet)
                    await asyncio.wait_for(writer.drain(), 2)
                    await asyncio.sleep(0.04)
            client.write(b'OK\n')
            log('hisight_input_sent', kind='key' if 'key' in item else 'tap')
        except (ValueError, TypeError, KeyError, ProtocolError, OSError, asyncio.TimeoutError):
            client.write(b'ERROR\n')
        finally:
            client.close()
            await client.wait_closed()
    server = None
    try:
        server = await asyncio.start_unix_server(command, str(path), limit=257)
        os.chmod(path, 0o600)
        log('hisight_input_ready')
        async with server:
            await server.serve_forever()
    finally:
        if server:
            server.close()
            await server.wait_closed()
            path.unlink(missing_ok=True)
        encoder.cipher.close()
