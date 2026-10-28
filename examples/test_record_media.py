"""Synthetic recorder boundary tests; no radio, phone or identity is used."""
import importlib.util
import io
import os
from pathlib import Path
import socket
import struct
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('record_media', Path(__file__).with_name('record_media.py'))
recorder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recorder)


def frame(kind, payload=b'', flags=0):
    return struct.pack('<IBBHQ', 12+len(payload), kind, flags, 0, 0)+payload


class RecorderTests(unittest.TestCase):
    def consume(self, data, maximum=1024):
        video, audio = io.BytesIO(), io.BytesIO()
        counts = dict(bytes=0, video_frames=0, audio_blocks=0, limit_reached=False)
        first, second = socket.socketpair()
        try:
            first.sendall(data)
            first.shutdown(socket.SHUT_WR)
            recorder.record(second, video, audio, time.monotonic()+1, maximum, counts)
        finally:
            first.close(); second.close()
        return video.getvalue(), audio.getvalue(), counts

    def test_source_fence_and_audio_gate(self):
        config = frame(1, struct.pack('<III', 800, 480, 30))
        data = config+frame(4, flags=1)+frame(2, b'old-p')+frame(2, b'idr', 1)
        data += frame(2, b'p')+frame(3, bytes(4))+frame(5, b'\x01')+frame(3, b'abcd')
        data += frame(6)+frame(2, b'dropped-p')+frame(2, b'new-idr', 1)
        data += frame(4)+frame(2, b'late-idr', 1)+frame(3, b'late')
        video, audio, counts = self.consume(data)
        self.assertEqual(video, b'idrpnew-idr')
        self.assertEqual(audio, b'abcd')
        self.assertEqual(counts['video_frames'], 3)

    def test_total_limit_and_malformed_record(self):
        data = frame(1, struct.pack('<III', 800, 480, 30))+frame(4, flags=1)
        data += frame(2, b'12345', 1)+frame(2, b'67890')
        video, _audio, counts = self.consume(data, maximum=8)
        self.assertEqual(video, b'12345')
        self.assertTrue(counts['limit_reached'])
        for malformed in (struct.pack('<I', 11), struct.pack('<I', 12+recorder.MAX_PAYLOAD+1),
                          frame(99), frame(3, b'bad'), frame(4, b'bad'), b'\x0c\x00'):
            with self.subTest(size=len(malformed)), self.assertRaises(ValueError):
                self.consume(malformed)

    def test_duration_is_not_extended_by_partial_record(self):
        first, second = socket.socketpair()
        try:
            first.sendall(b'\x0c')
            with self.assertRaises(TimeoutError):
                recorder.exact(second, 4, time.monotonic()+0.02)
        finally:
            first.close(); second.close()

    @unittest.skipUnless(os.name == 'posix', 'Linux ownership and Unix endpoints')
    def test_stale_cleanup_preserves_active_socket_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'endpoint'
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as live:
                live.bind(str(path)); live.listen(1)
                with self.assertRaises(ValueError): recorder.stale_socket(path)
                self.assertTrue(path.exists())
            recorder.stale_socket(path)
            self.assertFalse(path.exists())
            path.write_bytes(b'keep')
            with self.assertRaises(ValueError): recorder.stale_socket(path)
            self.assertEqual(path.read_bytes(), b'keep')
            path.unlink(); path.symlink_to(Path(root)/'missing')
            with self.assertRaises(ValueError): recorder.stale_socket(path)
            self.assertTrue(path.is_symlink())


if __name__ == '__main__':
    unittest.main()
