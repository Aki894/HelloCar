#!/usr/bin/env python3
"""Bounded Linux CL socket recorder; no identity/PIN/authentication capture."""
import argparse
import errno
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time

MAX_PAYLOAD = 512 * 1024


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise ValueError('directory must be owned by this UID with mode 0700')


def stale_socket(path):
    try:
        before = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.geteuid():
        raise ValueError('existing endpoint is not an owned socket')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as check:
        check.settimeout(0.2)
        result = check.connect_ex(str(path))
    if result != errno.ECONNREFUSED:
        raise ValueError('socket has an active or unverified owner')
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_uid, after.st_mode) != (
            before.st_dev, before.st_ino, before.st_uid, before.st_mode):
        raise ValueError('socket changed during ownership check')
    path.unlink()


def exact(peer, size, deadline):
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        peer.settimeout(remaining)
        chunk = peer.recv(size - len(data))
        if not chunk:
            if data:
                raise ValueError('truncated media record')
            return None
        data.extend(chunk)
    return bytes(data)


def record(peer, video, audio, deadline, maximum, counts):
    active = configured = False
    audio_active = set()
    wait_key = True
    while counts['bytes'] < maximum:
        header = exact(peer, 4, deadline)
        if header is None:
            return
        size, = struct.unpack('<I', header)
        if not 12 <= size <= 12 + MAX_PAYLOAD:
            raise ValueError('media record exceeds bounds')
        wire = exact(peer, size, deadline)
        if wire is None:
            raise ValueError('missing media record')
        kind, flags, reserved, _pts = struct.unpack('<BBHQ', wire[:12])
        payload = wire[12:]
        if reserved or flags & ~3:
            raise ValueError('invalid record flags')
        output = None
        if kind == 1:
            if flags or len(payload) != 12 or struct.unpack('<III', payload) != (800, 480, 30):
                raise ValueError('unsupported media configuration')
            configured = True
        elif kind == 4:
            if payload or flags > 1:
                raise ValueError('invalid source-state record')
            active = bool(flags)
            wait_key = True
        elif kind == 5:
            if flags not in (0, 3) or payload not in (b'\x00', b'\x01'):
                raise ValueError('invalid audio-state record')
            if payload == b'\x01':
                audio_active.add(flags)
            else:
                audio_active.discard(flags)
        elif kind == 7:
            request = json.loads(payload)
            if (flags or not isinstance(request, dict) or type(request.get('generation')) is not int or request['generation'] <= 0
                    or type(request.get('active')) is not bool or request.get('sample_rate') != 16000
                    or request.get('channels') != 1):
                raise ValueError('invalid microphone request')
            # The recorder does not acquire or return microphone audio.
        elif kind == 6:
            if flags or payload:
                raise ValueError('invalid video fence')
            wait_key = True
        elif kind == 2:
            if flags > 1:
                raise ValueError('invalid video flags')
            if not active or not configured or not payload or wait_key and not flags:
                continue
            wait_key = False
            output = video
        elif kind == 3:
            if flags not in (0, 3) or not payload or len(payload) % 4:
                raise ValueError('invalid PCM record')
            if active and flags in audio_active:
                output = audio
        else:
            raise ValueError('unknown output record')
        if output is not None:
            if counts['bytes'] + len(payload) > maximum:
                counts['limit_reached'] = True
                return
            output.write(payload)
            counts['bytes'] += len(payload)
            counts['video_frames' if kind == 2 else 'audio_blocks'] += 1


def run(path, output, duration, max_bytes):
    if os.name != 'posix' or not hasattr(socket, 'SO_PEERCRED'):
        raise ValueError('example requires Linux Unix sockets and SO_PEERCRED')
    private_directory(path.parent)
    private_directory(output)
    stale_socket(path)
    deadline = time.monotonic() + duration
    counts = dict(bytes=0, video_frames=0, audio_blocks=0, connections=0, limit_reached=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    identity = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            os.chmod(path, 0o600)
            info = path.lstat()
            identity = (info.st_dev, info.st_ino)
            server.listen(1)
            with os.fdopen(os.open(output/'video.h264', flags, 0o600), 'wb') as video:
                with os.fdopen(os.open(output/'audio.s16le', flags, 0o600), 'wb') as audio:
                    print(json.dumps(dict(event='listening', duration=duration, max_bytes=max_bytes)), flush=True)
                    while time.monotonic() < deadline and counts['bytes'] < max_bytes and not counts['limit_reached']:
                        server.settimeout(max(0.001, deadline-time.monotonic()))
                        with server.accept()[0] as peer:
                            _pid, uid, _gid = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                            if uid != os.geteuid():
                                raise ValueError('media peer UID differs from recorder')
                            counts['connections'] += 1
                            record(peer, video, audio, deadline, max_bytes, counts)
    except (TimeoutError, KeyboardInterrupt):
        pass
    finally:
        if identity is not None:
            try:
                info = path.lstat()
                if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == identity:
                    path.unlink()
            except FileNotFoundError:
                pass
    print(json.dumps(dict(event='finished', **counts)), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path, default=Path('/run/hellocar/media.sock'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--duration', type=int, default=60)
    parser.add_argument('--max-mib', type=int, default=64)
    args = parser.parse_args()
    if (not args.socket.is_absolute() or not args.output.is_absolute()
            or not 1 <= args.duration <= 3600 or not 1 <= args.max_mib <= 4096):
        parser.error('absolute paths, duration 1..3600 and max-mib 1..4096 required')
    os.umask(0o077)
    try:
        run(args.socket, args.output, args.duration, args.max_mib * 1024 * 1024)
    except (OSError, ValueError):
        parser.exit(1, 'recorder failed: check private paths, ownership and media framing\n')


if __name__ == '__main__':
    main()
