"""Bounded speaker datagrams and four-timestamp DMSDP clock sampling."""
import asyncio
import json
import os
from pathlib import Path
import socket
import struct
import time
from cipher import Cipher
from control_wire import pack_frame
from nearby_wire import ProtocolError
from audio_media import Audio


def unpack_datagram(data, cipher):
    if len(data) < 3 or int.from_bytes(data[1:3], 'big') != len(data) - 3:
        raise ProtocolError('invalid UDP record length')
    if data[0] != 0xab:
        raise ProtocolError('unencrypted UDP record')
    return cipher.decrypt(data[3:])


class Clock:
    def __init__(self):
        self.offset_us = None
        self.rtt_us = None
        self.updated_us = None

    def update(self, offset, rtt, now):
        self.offset_us, self.rtt_us, self.updated_us = offset, rtt, now

    def local_rtp_time(self, timestamp, now):
        if self.offset_us is None or now-self.updated_us > 60000000:
            return None
        peer_ticks = (now+self.offset_us)*90000//1000000
        delta = ((timestamp-(peer_ticks & 0xffffffff)+0x80000000) & 0xffffffff)-0x80000000
        return (peer_ticks+delta)*1000000//90000-self.offset_us


async def synchronize(local_ip, remote_ip, port, key, log, clock=None):
    cipher = Cipher(key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        sock.bind((local_ip, 0))
        sock.connect((remote_ip, port))
        while True:
            samples = []
            for _ in range(5):
                sent = time.monotonic_ns() // 1000
                request = struct.pack('<qqqq', sent, 0, 0, 0)
                await loop.sock_sendall(sock, pack_frame(cipher.encrypt(request), 0xab))
                try:
                    async with asyncio.timeout(.5):
                        while True:
                            data = await loop.sock_recv(sock, 1500)
                            arrived = time.monotonic_ns() // 1000
                            decoded = unpack_datagram(data, cipher)
                            if len(decoded) != 32:
                                continue
                            t1, t2, t3, _ = struct.unpack('<qqqq', decoded)
                            if t1 != sent or t3 < t2:
                                continue
                            rtt = (arrived - t1) - (t3 - t2)
                            if 0 <= rtt <= 100000:
                                samples.append((rtt, ((t2-t1)+(t3-arrived))//2))
                            break
                except (TimeoutError, ProtocolError):
                    pass
                await asyncio.sleep(.02)
            if samples:
                rtt, offset = min(samples)
                if clock:
                    clock.update(offset, rtt, time.monotonic_ns()//1000)
                log('clock_synchronized', samples=len(samples), rtt_us=rtt, offset_us=offset)
            else:
                log('clock_sample_timeout')
            await asyncio.sleep(30)
    except OSError as error:
        log('clock_stopped', error=type(error).__name__)
    finally:
        sock.close()
        cipher.close()


class Receiver:
    def __init__(self, local_ip, remote_ip, key, capture_dir, log, sink=None):
        self.remote_ip, self.capture_dir, self.log = remote_ip, capture_dir, log
        self.sink = sink
        self.cipher = Cipher(key, 65536)
        self.audio = Audio()
        self.clock = Clock()
        self.active = False
        self.generation = 0
        self.sockets = []
        try:
            for _ in range(1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sockets.append(sock)
                sock.setblocking(False)
                sock.bind((local_ip, 0))
        except BaseException:
            self.close()
            raise
        # HiCar speaker uses RTP without RTCP. A positive RTCP port conflicts
        # with the source's disabled-RTCP mode and rejects InitAsync.
        self.ports = (self.sockets[0].getsockname()[1], -1)

    def begin(self):
        self.active = False
        self.generation += 1
        self.audio.streams.clear()
        if self.sink:
            self.sink.audio_stop()

    async def receive(self, index):
        sock = self.sockets[index]
        stream = plain_stream = timeline = None
        media_files = {}
        total = count = 0
        saved_media = 0
        started = last_report = time.monotonic()
        invalid = 0
        try:
            if self.capture_dir:
                path = Path(self.capture_dir) / ('audio-%d-%d.udp' % (time.time_ns(), index))
                stream = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
                plain_stream = os.fdopen(os.open(str(path)+'.plain', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
                timeline = os.fdopen(os.open(str(path)+'.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w')
            while True:
                data, peer = await asyncio.get_running_loop().sock_recvfrom(sock, 65536)
                if peer[0] != self.remote_ip:
                    continue
                if not self.active:
                    continue
                count += 1
                try:
                    plain = unpack_datagram(data, self.cipher)
                    frames = self.audio.receive(plain)
                    if plain_stream and total + len(data) + 2 <= 32*1024*1024:
                        plain_stream.write(len(plain).to_bytes(2, 'big') + plain)
                        plain_stream.flush()
                    if count <= 3:
                        self.log('audio_plaintext', size=len(plain), version=plain[0] >> 6,
                                 payload_type=plain[1] & 127 if len(plain)>1 else -1)
                    for frame in frames:
                        if self.sink:
                            self.sink.audio(frame, time.monotonic_ns() // 1000, self.generation)
                        if self.audio.frames <= 3:
                            self.log('audio_format', codec='aac-adts', rate=frame['rate'],
                                     channels=frame['channels'])
                        if self.capture_dir and saved_media+len(frame['data']) <= 32*1024*1024:
                            file_id = (self.generation, frame['stream'])
                            if file_id not in media_files:
                                if len(media_files) >= 16:
                                    continue
                                name = str(path)+'.%d.%d.aac' % file_id
                                media_files[file_id] = os.fdopen(os.open(name,
                                    os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
                            media_files[file_id].write(frame['data'])
                            media_files[file_id].flush()
                            saved_media += len(frame['data'])
                            now = time.monotonic_ns()//1000
                            metadata = {k:v for k,v in frame.items() if k!='data'}
                            pts = self.clock.local_rtp_time(frame['rtp_timestamp'], now)
                            if pts is not None:
                                pts += frame['timestamp_offset_samples']*1000000//frame['rate']
                            metadata.update(generation=self.generation, received_us=now,
                                            local_pts_us=pts)
                            timeline.write(json.dumps(metadata)+'\n')
                            timeline.flush()
                except ProtocolError as error:
                    invalid += 1
                    if invalid <= 3:
                        self.log('audio_packet_rejected', reason=str(error))
                if stream and total + len(data) + 2 <= 32*1024*1024:
                    stream.write(len(data).to_bytes(2, 'big') + data)
                    stream.flush()
                    total += len(data) + 2
                if count <= 3 or count % 1000 == 0:
                    self.log('audio_datagram', channel=index, size=len(data), packets=count)
                if time.monotonic()-last_report >= 5:
                    self.log('audio_stats', packets=self.audio.packets, frames=self.audio.frames,
                        samples=self.audio.samples, lost=self.audio.lost, duplicates=self.audio.duplicates,
                        rejected=invalid, elapsed=round(time.monotonic()-started,3))
                    last_report = time.monotonic()
        except OSError as error:
            self.log('audio_receive_stopped', error=type(error).__name__)
        finally:
            if stream:
                stream.close()
            if plain_stream:
                plain_stream.close()
            if timeline:
                timeline.close()
            for media in media_files.values():
                media.close()
            self.log('audio_closed', packets=self.audio.packets, frames=self.audio.frames,
                     lost=self.audio.lost, rejected=invalid)

    def close(self):
        for sock in self.sockets:
            sock.close()
        self.cipher.close()
