"""HiSight state/RTSP differential checks; only generated keys and traffic."""
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests/reference'))
from cipher import Cipher
from hisight import Session, message

spec = importlib.util.spec_from_file_location('codec', ROOT / 'tools/test-hicar-rust.py')
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)


def check(binary):
    runner = json.loads(os.environ.get('HELLOCAR_RUST_RUNNER', '[]'))
    worker = codec.Process([*runner, binary, 'codec'])
    key = bytes(range(16))
    cipher = Cipher(key, 65001)
    def wire(data, encrypted=True):
        payload = cipher.encrypt(data) if encrypted else data
        return len(payload).to_bytes(4, 'big') + payload
    def plain(packet):
        assert int.from_bytes(packet[:4], 'big') == len(packet) - 4
        data = packet[4:]
        if data.startswith((b'RTSP/1.0 ', b'ANNOUNCE ', b'OPTIONS ')):
            return data
        return cipher.decrypt(data)
    announce = wire(message('ANNOUNCE * RTSP/1.0', 1,
        b'encrypt_description: encrypt_list=aes128ctr;version=1\r\n'), False)
    tail = [dict(receive=wire(message('OPTIONS * RTSP/1.0', 2)).hex()),
        dict(receive=wire(message('GET_PARAMETER * RTSP/1.0', 3,
            b'his_version\r\nhis_video_formats\r\nhis_vtp\r\nhis_uibc_capability\r\n')).hex()),
        dict(receive=wire(message('SET_PARAMETER * RTSP/1.0', 4,
            b'his_presentation_url: rtsp://192.168.49.2/hisight/streamid=0 none\r\n'
            b'his_trigger_method: SETUP\r\n')).hex()),
        dict(receive=wire(b'RTSP/1.0 200 OK\r\nCSeq: 3\r\nContent-Length: 60\r\n'
            b'Transport: RTP/AVP/UDP;server_port=49000;remotectl_port=49001;\r\n').hex()),
        dict(play=True), dict(receive=wire(message('GET_PARAMETER * RTSP/1.0', 5)).hex()),
        dict(teardown=True), dict(receive=wire(message('RTSP/1.0 200 OK', 5)).hex())]
    count = 0
    try:
        # Every split of the plaintext/encrypted transition, plus coalesced
        # records and each individual byte through the bounded stream parser.
        cases = [[dict(receive=announce[:n].hex()), dict(receive=announce[n:].hex()), *tail]
                 for n in range(len(announce) + 1)]
        cases.append([dict(receive=bytes([b]).hex()) for b in announce] + tail)
        cases.append([dict(receive=(announce+bytes.fromhex(tail[0]['receive'])).hex()), *tail[1:]])
        for steps in cases:
            reference = Session(key)
            result = worker.call(dict(op='hisight-session', key=key.hex(), steps=steps))
            assert result.get('ok'), f'Rust rejected valid HiSight case {count}'
            assert len(result['result']['steps']) == len(steps)
            for index, (step, actual) in enumerate(zip(steps, result['result']['steps'])):
                events, plaintexts = [], []
                if 'receive' in step:
                    events, plaintexts = reference.receive(bytes.fromhex(step['receive']))
                teardown = reference.teardown() if step.get('teardown') else None
                if step.get('play'):
                    reference.request('PLAY', {'Transport': 'RTP/AVP/UDP;unicast;client_port=0'})
                state = {name: getattr(reference, name) for name in ('encrypted', 'media_endpoint',
                    'input_endpoint', 'setup_sequence', 'peer_teardown', 'teardown_acknowledged')}
                assert actual['events'] == events, f'HiSight events differ: {count}/{index}'
                assert actual['state'] == state, f'HiSight state differs: {count}/{index}'
                assert actual['plaintexts'] == [p.hex() for p in plaintexts]
                assert [plain(bytes.fromhex(p)) for p in actual['pending']] == [plain(p) for p in reference.pending]
                assert (plain(bytes.fromhex(actual['teardown'])) if actual['teardown'] else None) == (plain(teardown) if teardown else None)
                reference.pending.clear()
            reference.close()
            count += 1
        malformed = [b'\0'*4, (65001).to_bytes(4, 'big'), wire(message('OPTIONS * RTSP/1.0', 1), False),
            wire(message('ANNOUNCE * RTSP/1.0', 1, b'encrypt_list=aes128gcm'), False),
            wire(b'ANNOUNCE * RTSP/1.0\r\nCSeq: 1\r\nCSeq: 2\r\n\r\naes128ctr', False),
            b'\0\0\0\x10'+bytes(16),
            wire(b'ANNOUNCE * RTSP/1.0\r\nCSeq: 1000000000\r\n\r\naes128ctr', False)]
        for data in malformed:
            result = worker.call(dict(op='hisight-session', key=key.hex(), steps=[dict(receive=data.hex())]))
            assert result.get('ok') is False, 'malformed HiSight accepted'
        # A malformed encrypted peer response must revoke an already opened
        # endpoint. These cases are rejected independently of Python tolerance.
        for payload in [b'RTSP/1.0 200 OK\r\nCSeq: -1\r\n\r\n',
            message('SET_PARAMETER * RTSP/1.0', 4, b'his_presentation_url: file:///tmp/no\r\n'),
            b'RTSP/1.0 200 OK\r\nCSeq: 3\r\nTransport: RTP/AVP/UDP;server_port=0\r\n\r\n']:
            result = worker.call(dict(op='hisight-session', key=key.hex(),
                steps=[dict(receive=announce.hex()), *tail[:3], dict(receive=wire(payload).hex())]))
            assert result.get('ok') is False, 'invalid encrypted HiSight accepted'
    finally:
        worker.close()
        cipher.close()
    print(json.dumps(dict(rust_hisight_transcripts='passed', cases=count, invalid_cases=len(malformed)+3,
        compressed_video_ipc=False)))


if __name__ == '__main__':
    check(str(Path(sys.argv[1]).resolve()))
