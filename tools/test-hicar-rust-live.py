"""Synthetic HiCar TCP/UDP/UIBC/native-decoder/live-socket integration.

No radio, USB, identity file or pairing database is used. The fake audio-only
decoder verifies process/pipe/pacing ownership; real AAC decoding has its own CI.
"""
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests/reference'))
from cipher import Cipher

KEY = bytes(range(16))


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size-len(data))
        if not chunk:
            raise AssertionError('synthetic socket closed early')
        data.extend(chunk)
    return bytes(data)


def rpc(sock, value):
    data = json.dumps(value).encode()
    sock.sendall(struct.pack('!I', len(data))+data)
    size, = struct.unpack('!I', exact(sock, 4))
    assert 0 < size <= 65536
    result = json.loads(exact(sock, size))
    assert result.get('ok') is True, result.get('error', 'private IPC failure')
    return result


def frame(sock):
    size, = struct.unpack('<I', exact(sock, 4))
    assert 12 <= size <= 512*1024+12
    data = exact(sock, size)
    kind, flags, reserved, pts = struct.unpack('<BBHQ', data[:12])
    assert not reserved
    return kind, flags, pts, data[12:]


def until_frame(sock, kind, predicate=lambda item: True, timeout=3):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        item = frame(sock)
        if item[0] == kind and predicate(item):
            return item
    raise AssertionError('expected media frame not received')


def feedback(sock, value):
    data = json.dumps(value).encode()
    sock.sendall(struct.pack('<IBBHQ', len(data)+12, 129, 0, 0, 0)+data)


def listener():
    value = socket.socket()
    value.bind(('127.0.0.1', 0))
    value.listen(4)
    value.settimeout(4)
    return value


def rtp_video(cipher, sequence, es, stamp=100):
    encrypted = cipher.encrypt(es)
    pes = b'\0\0\1\xe0'+(len(encrypted)+8).to_bytes(2, 'big')+b'\x84\x80\x05'+bytes(5)+encrypted
    packet = b'\x80\xe0'+sequence.to_bytes(2, 'big')+stamp.to_bytes(4, 'big')+bytes(4)+pes
    return len(packet).to_bytes(4, 'big')+packet


def audio_packet(cipher, sequence, stamp=100, stream=1003):
    # One legal ADTS header and four placeholder AAC bytes. The fake native
    # process deliberately only verifies bounded transport, not AAC syntax.
    adts = bytes([255, 241, 76, 128, 1, 127, 252, 0, 0, 0, 0])
    rtp = b'\x80\x60'+sequence.to_bytes(2, 'big')+stamp.to_bytes(4, 'big')+stream.to_bytes(4, 'big')+adts
    data = cipher.encrypt(rtp)
    return b'\xab'+len(data).to_bytes(2, 'big')+data


def clock_peer(server, failures):
    cipher = Cipher(KEY)
    try:
        for _ in range(5):
            data, peer = server.recvfrom(1500)
            assert data[0] == 0xab and int.from_bytes(data[1:3], 'big') == len(data)-3
            t1, _, _, _ = struct.unpack('<qqqq', cipher.decrypt(data[3:]))
            t2 = time.monotonic_ns()//1000+12345
            payload = cipher.encrypt(struct.pack('<qqqq', t1, t2, t2+1, 0))
            server.sendto(b'\xab'+len(payload).to_bytes(2, 'big')+payload, peer)
    except BaseException as error:
        failures.append(type(error).__name__)
    finally:
        cipher.close()


def check(binary):
    runner = json.loads(os.environ.get('HELLOCAR_RUST_RUNNER', '[]'))
    with tempfile.TemporaryDirectory(prefix='carlink-media-rust-') as directory:
        root = Path(directory)
        source = socket.socket(socket.AF_UNIX)
        source.bind(str(root/'live.sock'))
        source.listen(4)
        source.settimeout(4)
        video_server, input_server = listener(), listener()
        fake = root/'decoder.py'
        fake.write_text('''#!/usr/bin/env python3
import os,sys
encoder = 'adts' in sys.argv
if encoder:
    split = sys.argv.index('-i')
    before, after = sys.argv[:split], sys.argv[split+1:]
    assert before[before.index('-ar')+1] == '16000'
    assert before[before.index('-ac')+1] == '1'
    assert after[after.index('-ar')+1] == '48000'
    assert after[after.index('-ac')+1] == '2'
pending = bytearray()
while True:
    data = os.read(0,8192)
    if not data:
        break
    if encoder:
        pending.extend(data)
        while len(pending) >= 640:
            del pending[:640]
            os.write(1,bytes([255,241,76,128,1,127,252,0,0,0,0]))
    else:
        os.write(1,b"\\x01\\x00\\x02\\x00"*2646)
''', encoding='utf8')
        fake.chmod(0o755)
        ipc, child = socket.socketpair()
        ipc.settimeout(5)
        process = subprocess.Popen([*runner, binary, 'media-worker', str(child.fileno())],
            pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child.close()
        live = video = control = None
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clock.bind(('127.0.0.1', 0));clock.settimeout(3)
        clock_failures = []
        clock_thread = None
        cipher = Cipher(KEY, 2*1024*1024)
        try:
            ready = rpc(ipc, dict(key=KEY.hex(), local_ip='127.0.0.1', peer_ip='127.0.0.1',
                live_socket=str(root/'live.sock'), audio_binary=str(fake)))
            assert ready['ready'] and ready['audio_ports'][1] == -1
            audio_port = ready['audio_ports'][0]
            live, _ = source.accept()
            live.settimeout(4)
            until_frame(live, 4, lambda f: f[1] == 0)
            configured = until_frame(live, 1)
            assert struct.unpack('<III', configured[3]) == (800, 480, 30)
            rpc(ipc, dict(op='set-video', media_port=video_server.getsockname()[1],
                input_port=input_server.getsockname()[1]))
            video, _ = video_server.accept()
            control, _ = input_server.accept()
            control.settimeout(4)
            idr = b'\0\0\0\1\x67synthetic-sps\0\0\0\1\x68synthetic-pps\0\0\0\1\x65synthetic-idr'
            video.sendall(rtp_video(cipher, 0xfffe, b'\0\0\0\1\x41first-predicted'))
            video.sendall(rtp_video(cipher, 0xffff, b'\0\0\0\1\x65idr-without-parameters'))
            time.sleep(.03)
            not_ready = rpc(ipc, dict(op='status'))['state']
            assert not not_ready['active'] and not_ready['epoch_video_frames'] == 0
            video.sendall(rtp_video(cipher, 1, idr))
            delivered = until_frame(live, 2)
            assert delivered[1] == 1 and delivered[3].endswith(idr)
            # A decoder recovery fence pauses predicted output, not the
            # established phone transport. It must not reopen the menu.
            feedback(live, dict(type='keyframe'))
            until_frame(live, 6)
            recovering = rpc(ipc, dict(op='status'))['state']
            assert recovering['active'] and recovering['waiting_key']
            video.sendall(rtp_video(cipher, 2, b'\0\0\0\1\x41recovery-predicted'))
            time.sleep(.03)
            assert rpc(ipc, dict(op='status'))['state']['epoch_video_frames'] == 1
            video.sendall(rtp_video(cipher, 3, idr))
            # Any spurious inactive session notification fails this fence.
            while True:
                resumed = frame(live)
                assert resumed[0] != 4 or resumed[1] != 0
                if resumed[0] == 2:
                    break
            assert resumed[1] == 1
            # Valid RTP/PES and AES framing can still contain malformed ES.
            # Reject it before CarLife, fence dependent pictures, and preserve
            # the established phone session while awaiting a genuine IDR.
            before_bad = rpc(ipc, dict(op='status'))['state']
            malformed = (b'no-annexb-start-code', b'\0\0\0\1\xe5forbidden-bit',
                         b'\0\0\0\1', b'garbage\0\0\1\x41predicted')
            for sequence, es in enumerate(malformed, 4):
                video.sendall(rtp_video(cipher, sequence, es))
                until_frame(live, 6)
            rejected = rpc(ipc, dict(op='status'))['state']
            assert rejected['rejected'] == before_bad['rejected'] + len(malformed)
            assert rejected['epoch_video_frames'] == before_bad['epoch_video_frames']
            assert rejected['active'] and rejected['waiting_key']
            video.sendall(rtp_video(cipher, 8, b'\0\0\0\1\x41after-malformed'))
            time.sleep(.03)
            assert rpc(ipc, dict(op='status'))['state']['epoch_video_frames'] == before_bad['epoch_video_frames']
            video.sendall(rtp_video(cipher, 9, idr))
            recovered = until_frame(live, 2)
            assert recovered[1] == 1 and recovered[3].endswith(idr)
            feedback(live, dict(type='touch', contacts=[dict(x=.2, y=.3, down=True)]))
            feedback(live, dict(type='touch', contacts=[dict(x=.4, y=.6, down=True)]))
            feedback(live, dict(type='touch', contacts=[]))
            feedback(live, dict(type='key-press', code=1))
            feedback(live, dict(type='key-press', code=7))
            feedback(live, dict(type='key-press', code=8))
            feedback(live, dict(type='key-press', code=9))
            actions = []
            keys = []
            for _ in range(11):
                header = exact(control, 4)
                assert header[:2] == bytes(2)
                size = int.from_bytes(header[2:], 'big')
                body = cipher.decrypt(exact(control, size-4))
                assert body[:6] == b'\xff'*6
                actions.append(body[6])
                if body[6] in (3, 4):
                    keys.append(int.from_bytes(body[10:12], 'big'))
            assert actions == [0, 2, 1, 3, 4, 3, 4, 3, 4, 3, 4], 'touch/key edges differ from the observed source contract'
            assert keys == [4, 4, 85, 85, 87, 87, 88, 88], 'media skip keys differ from the Android key contract'
            rpc(ipc, dict(op='audio-begin'))
            rpc(ipc, dict(op='audio-ready'))
            udp.sendto(audio_packet(cipher, 1), ('127.0.0.1', audio_port))
            first_pcm = until_frame(live, 3)
            assert len(first_pcm[3]) == 3528 and any(first_pcm[3])
            assert len(until_frame(live, 3)[3]) == 3528
            assert len(until_frame(live, 3)[3]) == 3528
            status = rpc(ipc, dict(op='status'))['state']
            # The fake decoder writes exactly three 20 ms blocks at once. All
            # three survive IO pumping until the single playout clock consumes
            # them; none can overwrite a pending block in a second mixer timer.
            assert status['active'] and status['audio_frames'] == 1 and status['pcm_blocks'] == 3
            assert isinstance(status['audio_underruns'], int) and isinstance(status['mix_late'], int)
            assert status['pcm_queued_blocks'] <= 6
            # SSRCs must own distinct decoders; align their PCM at one output tick.
            udp.sendto(audio_packet(cipher, 2, 200), ('127.0.0.1', audio_port))
            udp.sendto(audio_packet(cipher, 1, 200, stream=2004), ('127.0.0.1', audio_port))
            mixed = until_frame(live, 3, lambda f: f[3][:4] == bytes([2,0,4,0]))
            assert len(mixed[3]) == 3528
            assert rpc(ipc, dict(op='status'))['state']['audio_streams'] == 2
            assert status['input_events'] == 7
            assert status['epoch_video_frames'] == 3
            # A route can restart sequence zero on the same SSRC. Its fresh
            # session must not wait for the old route's sequence to catch up.
            call_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            call_udp.bind(('127.0.0.1', 0))
            try:
                rpc(ipc, dict(op='audio-service', service='speaker1', active=True, port=udp.getsockname()[1]))
                before_route = rpc(ipc, dict(op='status'))['state']['audio_frames']
                udp.sendto(audio_packet(cipher, 0), ('127.0.0.1', audio_port))
                until_frame(live, 3)
                assert rpc(ipc, dict(op='status'))['state']['audio_frames'] == before_route+1
                rpc(ipc, dict(op='audio-service', service='modemSpeaker', active=True, port=call_udp.getsockname()[1]))
                rpc(ipc, dict(op='audio-role', role=3))
                rpc(ipc, dict(op='audio-ready'))
                during_call = rpc(ipc, dict(op='status'))['state']['audio_frames']
                udp.sendto(audio_packet(cipher, 1), ('127.0.0.1', audio_port))
                call_udp.sendto(audio_packet(cipher, 0), ('127.0.0.1', audio_port))
                until_frame(live, 3, lambda f: f[1] == 3)
                assert rpc(ipc, dict(op='status'))['state']['audio_frames'] == during_call+1
                rpc(ipc, dict(op='audio-role', role=0))
                rpc(ipc, dict(op='audio-ready'))
                udp.sendto(audio_packet(cipher, 0), ('127.0.0.1', audio_port))
                until_frame(live, 3, lambda f: f[1] == 0)
                assert rpc(ipc, dict(op='status'))['state']['audio_frames'] == during_call+2
                rpc(ipc, dict(op='audio-service', service='modemSpeaker', active=False))
                rpc(ipc, dict(op='audio-service', service='speaker1', active=False))
            finally:
                call_udp.close()
            # Datagram framing and selected source checks reject unexpected
            # senders independently of the connected TCP control session.
            udp.sendto(b'\xab\0\0wrong', ('127.0.0.1', audio_port))
            time.sleep(.03)
            assert rpc(ipc, dict(op='status'))['state']['rejected'] >= 1
            rpc(ipc, dict(op='audio-stop'))
            until_frame(live, 5, lambda f: f[3] == b'\0')
            clock_thread = threading.Thread(target=clock_peer, args=(clock, clock_failures), daemon=True)
            clock_thread.start()
            rpc(ipc, dict(op='clock-start', port=clock.getsockname()[1]))
            clock_thread.join(3)
            assert not clock_thread.is_alive() and not clock_failures, 'clock sampling failed'
            deadline = time.monotonic()+1
            while time.monotonic() < deadline:
                synced = rpc(ipc, dict(op='status'))['state']
                if synced['clock_updated_us'] is not None:
                    break
                time.sleep(.02)
            assert synced['clock_updated_us'] is not None and abs(synced['clock_offset_us']-12345) < 5000
            # Broken feedback after a held contact must release the contact,
            # reconnect the live transport, and wait for another genuine IDR.
            feedback(live, dict(type='touch', contacts=[dict(x=.1, y=.2, down=True)]))
            header = exact(control, 4)
            assert cipher.decrypt(exact(control, int.from_bytes(header[2:], 'big')-4))[6] == 0
            live.sendall(struct.pack('<IBBHQ', 14, 129, 1, 0, 0)+b'{}')
            header = exact(control, 4)
            assert cipher.decrypt(exact(control, int.from_bytes(header[2:], 'big')-4))[6] == 1
            live.close();live = None
            live, _ = source.accept();live.settimeout(4)
            until_frame(live, 1)
            video.sendall(rtp_video(cipher, 10, idr, 1000))
            until_frame(live, 2)
            # An input TCP reset is isolated from video. The next input opens a
            # new channel and sends releases before any new key edge.
            control.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            control.close();control = None
            feedback(live, dict(type='key-press', code=2))
            time.sleep(.1)
            feedback(live, dict(type='key-press', code=1))
            control, _ = input_server.accept();control.settimeout(4)
            restored = []
            for _ in range(3):
                header = exact(control, 4)
                restored.append(cipher.decrypt(exact(control, int.from_bytes(header[2:], 'big')-4))[6])
            assert restored[-2:] == [3, 4]
            # The old decoder can have PCM buffered. Stop must kill it and
            # remove pending old PCM; packets arriving while stopped are ignored.
            stopped_pcm = rpc(ipc, dict(op='status'))['state']['pcm_blocks']
            udp.sendto(audio_packet(cipher, 2), ('127.0.0.1', audio_port))
            time.sleep(.08)
            assert rpc(ipc, dict(op='status'))['state']['pcm_blocks'] == stopped_pcm
            rpc(ipc, dict(op='audio-begin'))
            rpc(ipc, dict(op='audio-ready'))
            udp.sendto(audio_packet(cipher, 3, 300), ('127.0.0.1', audio_port))
            assert len(until_frame(live, 3)[3]) == 3528
            assert rpc(ipc, dict(op='status'))['state']['audio_generation'] == 2
            rpc(ipc, dict(op='audio-stop'))
            until_frame(live, 5, lambda f: f[3] == b'\0')
            # A private owner stop signal must not kill media before the RTSP
            # adapter has sent teardown and closed its IPC endpoint.
            process.send_signal(signal.SIGTERM)
            assert rpc(ipc, dict(op='status'))['state']['video_open']
            # CarLife source reconnect keeps the compressed stream bounded and
            # restores only at a genuine IDR, with cached SPS/PPS.
            live.close();live = None
            live, _ = source.accept()
            live.settimeout(4)
            until_frame(live, 1)
            video.sendall(rtp_video(cipher, 2, b'\0\0\0\1\x41predicted', 200))
            time.sleep(.03)
            assert rpc(ipc, dict(op='status'))['state']['waiting_key']
            video.sendall(rtp_video(cipher, 3, b'\0\0\0\1\x65recovery-idr', 300))
            assert until_frame(live, 2)[1] == 1
            # Binary HU microphone -> native AAC encoder -> encrypted UDP RTP.
            microphone_peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            microphone_peer.bind(('127.0.0.1', 0)); microphone_peer.settimeout(2)
            try:
                rpc(ipc, dict(op='microphone-start', port=microphone_peer.getsockname()[1], session=7))
                request = json.loads(until_frame(live, 7)[3])
                assert request['active'] and request['sample_rate'] == 16000
                payload = struct.pack('<Q', request['generation']) + bytes(640)
                packet = struct.pack('<IBBHQ', 12+len(payload),130,0,0,0)+payload
                capture_before = time.monotonic_ns() // 1000
                live.sendall(packet + packet)
                origin = None
                for sequence in range(2):
                    encrypted, _ = microphone_peer.recvfrom(1500)
                    assert encrypted[0] == 0xab and int.from_bytes(encrypted[1:3],'big') == len(encrypted)-3
                    rtp = cipher.decrypt(encrypted[3:])
                    # DataSessionID=7 belongs to control; virtual mic RTP must
                    # select the separately registered AudioStream type 1100.
                    assert rtp[:2] == b'\x80\x60' and int.from_bytes(rtp[8:12],'big') == 1100
                    assert int.from_bytes(rtp[2:4],'big') == sequence
                    stamp = int.from_bytes(rtp[4:8], 'big')
                    if origin is None:
                        origin = stamp
                        lower = (capture_before+synced["clock_offset_us"]) * 90000 // 1000000 & 0xffffffff
                        upper = (time.monotonic_ns() // 1000+synced["clock_offset_us"]) * 90000 // 1000000 & 0xffffffff
                        assert (stamp-lower) & 0xffffffff <= (upper-lower) & 0xffffffff
                    assert (stamp-origin) & 0xffffffff == sequence * 1920
                    assert rtp[12:16] == bytes([255,241,76,128])  # AAC-LC, 48k stereo
                rpc(ipc, dict(op='microphone-stop'))
                assert not json.loads(until_frame(live,7)[3])['active']
                live.sendall(struct.pack('<IBBHQ', 12+len(payload),130,0,0,0)+payload)
                microphone_peer.settimeout(.1)
                try:
                    microphone_peer.recvfrom(1500)
                    raise AssertionError('microphone packet after stop')
                except socket.timeout:
                    pass
                # A modem microphone keeps the call lifetime active after its
                # playback service stops; ending it then releases call mode.
                rpc(ipc, dict(op='microphone-start', port=microphone_peer.getsockname()[1], session=8, service='modemMic'))
                assert json.loads(until_frame(live,7)[3])['active']
                rpc(ipc, dict(op='audio-role', role=3))
                until_frame(live,5,lambda f: f[1]==3 and f[3]==b'\1')
                rpc(ipc, dict(op='audio-stop'))
                until_frame(live,5,lambda f: f[1]==3 and f[3]==b'\0')
                until_frame(live,5,lambda f: f[1]==3 and f[3]==b'\1')
                assert rpc(ipc, dict(op='status'))['state']['call_active']
                rpc(ipc, dict(op='microphone-stop', service='modemMic'))
                assert not json.loads(until_frame(live,7)[3])['active']
                rpc(ipc, dict(op='audio-role', role=0))
                until_frame(live,5,lambda f: f[1]==3 and f[3]==b'\0')
                assert not rpc(ipc, dict(op='status'))['state']['call_active']
            finally:
                microphone_peer.close()
            # EOF must turn the source inactive immediately, even when the
            # separate RTSP control socket remains open.
            video.close();video = None
            until_frame(live, 4, lambda f: f[1] == 0)
            ended = rpc(ipc, dict(op='status'))['state']
            assert ended['video_ended'] and not ended['active'] and not ended['video_open']
            # A new epoch cannot report readiness using the previous epoch's
            # cumulative frame count before receiving its own valid IDR.
            rpc(ipc, dict(op='set-video', media_port=video_server.getsockname()[1],
                input_port=None))
            video, _ = video_server.accept()
            restarted = rpc(ipc, dict(op='status'))['state']
            assert restarted['epoch_video_frames'] == 0 and not restarted['active']
            assert rpc(ipc, dict(op='close'))['closed']
            assert process.wait(timeout=3) == 0
        finally:
            ipc.close()
            child.close()
            if process.poll() is None:
                process.kill();process.wait(timeout=3)
            for stream in (live, video, control, source, video_server, input_server, udp):
                if stream is not None:
                    stream.close()
            cipher.close()
            clock.close()
            if clock_thread:
                clock_thread.join(1)
    print(json.dumps(dict(rust_media_io='passed', h264_passthrough=True, encrypted_video=True,
        udp_audio_native_process_pcm=True, touch_move_release=True, eof_source_inactive=True,
        carlife_reconnect_idr=True, audio_generation_isolated=True, clock_four_timestamp=True,
        broken_feedback_release=True, input_reconnect=True, epoch_readiness=True,
        malformed_annexb_recovery=True, private_ipc_only=True)))


if __name__ == '__main__':
    check(str(Path(sys.argv[1]).resolve()))
