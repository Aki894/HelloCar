import struct
import unittest
from microphone_pcm import microphone_record


class MicrophoneRecordTests(unittest.TestCase):
    def test_binary_frame_keeps_generation_and_pcm(self):
        raw = microphone_record(17, bytes(640), 500)
        self.assertEqual(struct.unpack_from('<IBBHQ', raw), (660,130,0,0,500))
        self.assertEqual(struct.unpack_from('<Q', raw, 16)[0],17)
        self.assertEqual(raw[24:], bytes(640))

    def test_invalid_generation_and_buffers(self):
        for generation, pcm in [(0, bytes(2)), (True, bytes(2)), (1, b'x'), (1, bytes(16386))]:
            with self.assertRaises(ValueError): microphone_record(generation, pcm)
