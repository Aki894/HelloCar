"""R2 state transcripts and private-IPC native authentication; synthetic identities only."""
import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import signal
import socket
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests/reference'))
from nearby_wire import Frame, pack_tlv, pack_uint
from control import Negotiator
from network import Offer
from network_wire import Resource

spec = importlib.util.spec_from_file_location('hicar_codec', ROOT / 'tools/test-hicar-rust.py')
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)


def transcript(binary):
    process = codec.Process([*json.loads(os.environ.get('HELLOCAR_RUST_RUNNER', '[]')),
                             binary, 'codec'])
    offer = Offer('HelloCar', '02:00:00:00:00:01', 'synthetic-password')
    summary = b'A' * 64
    prefix = [Frame(0, 0, b'', pack_tlv(1, b'\x02')),
              Frame(0, 0, b'', pack_tlv(3, b'peer-summary')),
              Frame(0, 0, b'', pack_tlv(5, b'\x00'))]
    def capability(caps):
        body = b''.join(pack_uint(k) + pack_uint(v) for k, v in caps.items())
        return Frame(4, 0, b'', pack_tlv(1, pack_uint(3) + pack_tlv(3, body)))
    supported = capability({2: 1, 4: 1, 5: 511})
    selected = Frame(4, 0, b'', pack_tlv(7, pack_uint(3) + pack_uint(1) +
                                                       pack_tlv(3, b'\x02' + pack_uint(5745))))
    cases = []
    for authenticated in (False, True):
        cases.extend((authenticated, frames) for frames in [prefix,
            prefix + [supported, selected, Frame(33, 0, b'', pack_tlv(2, b'02:00:00:00:00:02'))],
            prefix + [Frame(2, 0, b'', pack_tlv(3, pack_uint(2) + pack_uint(19) + pack_uint(0) + pack_uint(0)))],
            prefix + [supported, Frame(4, 0, b'', pack_tlv(3, pack_uint(3) + pack_uint(20) + pack_uint(0) + pack_uint(1)))],
            prefix + [Frame(33, 0, b'', pack_tlv(2, b'02:00:00:00:00:02'))],
            prefix + [supported, Frame(33, 1, b'', pack_tlv(2, b'02:00:00:00:00:02'))],
            prefix + [supported, Frame(33, 0, b'', pack_tlv(2, b'not-a-MAC'))],
            prefix + [supported, Frame(33, 0, b'', pack_tlv(1, b''))],
            prefix + [supported, Frame(33, 0, b'', pack_tlv(5, b''))]])
    rng = random.Random(20261025)
    for _ in range(160):
        caps = {2: rng.randrange(3), 4: rng.randrange(3), 5: rng.randrange(512)}
        cases.append((True, prefix + [capability(caps)]))
    for payload in [b'', pack_tlv(1, b''), pack_tlv(1, b'\x01'),
                    pack_tlv(5, b'\x03'), pack_tlv(3, b''), b'\x81']:
        cases.append((True, [Frame(0, 0, b'', payload)]))
    try:
        for index, (authenticated, frames) in enumerate(cases):
            resource = Resource(offer)
            resource.authenticated = authenticated
            resource.data_port = 4006
            n = Negotiator(summary, 24, resource)
            expected = []
            try:
                for frame in frames:
                    reply = n.respond(frame)
                    expected.append(dict(reply=reply.hex() if reply is not None else None,
                        complete=n.complete, pending=[[k, p.hex()] for k, p in resource.take_pending()],
                        credentials_sent=resource.credentials_sent))
                success = True
            except (ValueError, UnicodeError):
                success = False
            result = process.call(dict(op='nearby-session', offer=dataclasses.asdict(offer),
                summary=summary.hex(), business=24, authenticated=authenticated,
                frames=[dict(kind=f.kind, flags=f.flags, payload=f.payload.hex()) for f in frames]))
            assert result.get('ok') is success, f'connection acceptance differs in case {index}'
            if success:
                assert result['result'] == dict(steps=expected), f'connection reply differs in case {index}'
    finally:
        process.close()
    print(json.dumps(dict(rust_connection_transcripts='passed', cases=len(cases))))


def authentication(binary, library, rust_library):
    from rust_session import Worker, AuthSession as RustAuth, Negotiator as RustNegotiator, HiSightSession
    from hisight import message
    from cipher import Cipher
    from identity import Identity
    from auth_wire import JsonStream, AuthError
    from control_wire import Decoder as ControlDecoder, Messages, pack_frame
    offer = Offer('HelloCar', '02:00:00:00:00:01', 'synthetic-password')
    model, address = '00040A00', '02:11:22:33:44:55'
    stored = Identity('AB' * 32, '012345')
    own = stored.for_adapter(model, address).device_id
    client_id = 'CD' * 32
    runner = json.loads(os.environ.get('HELLOCAR_RUST_RUNNER', '[]'))
    results = []
    def rejected(worker, command, label):
        try:
            worker.call(command)
        except ValueError:
            return
        raise AssertionError(label)

    def control_text(start, sequence, **headers):
        return ('\r\n'.join([start, 'CSeq: '+str(sequence)] +
            [name+': '+str(value) for name, value in headers.items()])+'\r\n\r\n').encode('ascii')

    def control_packet(packet, cipher=None):
        frames = ControlDecoder().feed(packet)
        assert len(frames) == 1
        payload = frames[0].payload
        if frames[0].marker == 0xab:
            assert cipher is not None
            payload = cipher.decrypt(payload)
        texts = Messages().feed(payload)
        assert len(texts) == 1
        return texts[0]
    with tempfile.TemporaryDirectory(prefix='hellocar-r2-') as directory:
        root = Path(directory)
        identity = root / 'identity.json'
        identity.write_bytes(stored.encoded())
        identity.chmod(0o600)
        original = identity.read_bytes()
        for phase in ('bind', 'auth'):
            w = p = auth = None
            try:
                w = Worker(binary, identity, model, address, rust_library, root / 'server',
                           offer, own.encode(), 24, runner=runner)
                resource = Resource(offer)
                # Prior to successful auth, even a negotiated data channel is gated.
                n = RustNegotiator(w, resource, True)
                for f in [Frame(0, 0, b'', pack_tlv(1, b'\x02') + pack_tlv(3, b'peer') + pack_tlv(5, b'\x00'))]:
                    n.respond(f)
                capability = b''.join(pack_uint(k) + pack_uint(v) for k, v in {2: 1, 4: 1, 5: 511}.items())
                network = Frame(4, 0, b'', pack_tlv(1, pack_uint(3) + pack_tlv(3, capability)))
                client_mac = Frame(33, 0, b'', pack_tlv(2, b'02:00:00:00:00:02'))
                assert n.respond(network) is None and n.respond(client_mac) is None
                auth = RustAuth(w)
                control_info = dict(deviceId=own, deviceName='HelloCar', deviceType=4,
                    bluetoothMac=address, btName='HelloCar', localIp=offer.owner_ip,
                    remoteIp=offer.client_ip, port=0, properties={'2003': model})
                rejected(w, dict(op='dmsdp-open', generation=auth.generation,
                    device_info=control_info, audio=True), 'DMSDP opened before authentication')
                try:
                    HiSightSession(w, auth.generation)
                except ValueError:
                    pass
                else:
                    raise AssertionError('HiSight opened before authentication')
                envelope = lambda op, data: (dict(version='14.2.0.400', oper_type=op, synctime=0,
                    trace_id='synthetic', data=json.dumps(data)) if phase == 'auth' else
                    dict(version='A_0', discover_type=1, oper_type=op, usb_connection=False, data=json.dumps(data)))
                reply, metadata = auth.receive(envelope(1, dict(deviceId=client_id, usb_connection=False)))
                assert metadata['operation'] == 1 and json.loads(json.loads(reply)['data'])['deviceId'] == own
                p = codec.Process([sys.executable, str(ROOT / 'tools/test-hicar-rust-auth.py'), '--python-worker'])
                assert p.call(dict(library=library, store=str(root / 'client'), hardwareSeed=client_id,
                    own=client_id, peer=own, pin=stored.pin, role=1))['ready']
                state = p.call(dict(op='begin', phase=phase))
                pending = [(True, packet) for packet in state['packets']]
                for _ in range(32):
                    if not pending:
                        break
                    to_rust, packet = pending.pop(0)
                    if to_rust:
                        reply, metadata = auth.receive(envelope(3, json.loads(packet)))
                        if reply:
                            stream = JsonStream()
                            pending.extend((False, item['data']) for item in stream.feed(reply))
                            stream.finish()
                    else:
                        state = p.call(dict(op='receive', data=packet))
                        pending.extend((True, packet) for packet in state['packets'])
                assert not pending and 0 in state['results'] and metadata.get('key_ready')
                assert hashlib.sha256(auth.session_key).hexdigest() == state['key_hash']
                assert len(auth.session_key) == (32 if phase == 'bind' else 16)
                assert n.respond(network) is not None
                assert offer.credentials() in n.respond(client_mac)
                # Exercise the actual authenticated private worker, rather
                # than passing a synthetic key straight to the codec command.
                control_open = dict(op='dmsdp-open', generation=auth.generation,
                    device_info=control_info, audio=True)
                first_control = w.call(control_open)
                assert control_packet(bytes.fromhex(first_control['initial'])).start == 'OPTIONS * DMSDP/1.0'
                rejected(w, control_open, 'duplicate DMSDP open accepted')
                first_token = first_control['session']
                assert w.call(dict(op='dmsdp-ports', session=first_token,
                    ports=[40000, -1]))['state']['speaker']['ports'] == [40000, -1]
                w.call(dict(op='dmsdp-close', session=first_token))
                control_token = w.call(control_open)['session']
                assert control_token != first_token
                for op in ('dmsdp-close', 'dmsdp-heartbeat', 'dmsdp-stop-audio'):
                    rejected(w, dict(op=op, session=first_token), 'stale DMSDP token accepted')
                assert w.call(dict(op='dmsdp-ports', session=control_token,
                    ports=[40002, -1]))['state']['speaker']['ports'] == [40002, -1]
                negotiation = pack_frame(control_text('SET_PARAMETER * DMSDP/1.0', 1,
                    CryptoVer=1, CryptoSwitch=222, CryptoAlg='aes128-ctr'))
                for index, fragment in enumerate((negotiation[:5], negotiation[5:])):
                    response = w.call(dict(op='dmsdp-receive', session=control_token,
                        data=fragment.hex(), now_us=123456, capture=True))
                    assert response['state']['negotiated'] is bool(index)
                # DMSDP emits the parsed-message metadata before its derived
                # state event, matching control_wire.Session and codec tests.
                assert response['events'] == [control_packet(negotiation).metadata(),
                    dict(negotiated=True, cipher='aes128-ctr')]
                assert control_packet(bytes.fromhex(response['pending'][0])).start == 'DMSDP/1.0 200 OK'
                with_cipher = Cipher(auth.session_key)
                try:
                    heart = w.call(dict(op='dmsdp-heartbeat', session=control_token))
                    assert control_packet(bytes.fromhex(heart['heartbeat']), with_cipher).start == 'GET_PARAMETER * DMSDP/1.0'
                    keepalive = control_text('GET_PARAMETER * DMSDP/1.0', 31)
                    wire = pack_frame(with_cipher.encrypt(keepalive), 0xab)
                    response = w.call(dict(op='dmsdp-receive', session=control_token,
                        data=wire.hex(), now_us=123457, capture=True))
                    assert response['events'] == [Messages().feed(keepalive)[0].metadata(),
                        dict(keepalive_received=True)]
                    assert response['plaintexts'] == [keepalive.hex()]
                finally:
                    with_cipher.close()
                sight = HiSightSession(w, auth.generation)
                initial = sight.initial()
                assert initial[4:].startswith(b'ANNOUNCE * RTSP/1.0')
                old_token = sight.session
                sight.close()
                sight = HiSightSession(w, auth.generation)
                try:
                    w.call(dict(op='hisight-close', session=old_token))
                except ValueError:
                    pass
                else:
                    raise AssertionError('stale HiSight cleanup accepted')
                announce = message('ANNOUNCE * RTSP/1.0', 1, b'encrypt_list=aes128ctr')
                sight.receive(len(announce).to_bytes(4, 'big') + announce)
                assert sight.encrypted
                # The owner gets a group stop signal before requesting RTSP
                # teardown. Its child must remain available until private EOF.
                w.process.send_signal(signal.SIGTERM)
                peer_cipher = Cipher(auth.session_key, 65001)
                try:
                    encrypted = peer_cipher.encrypt(message('GET_PARAMETER * RTSP/1.0', 2, b'his_version\r\n'))
                    sight.receive(len(encrypted).to_bytes(4, 'big') + encrypted)
                    assert b'his_version: 1.0' in peer_cipher.decrypt(sight.pending[-1][4:])
                finally:
                    peer_cipher.close()
                # A stale command must not revoke a newer active authentication.
                try:
                    w.call(dict(op='auth', generation=auth.generation + 1, envelope='{}'))
                except ValueError:
                    pass
                else:
                    raise AssertionError('stale authentication generation accepted')
                assert offer.credentials() in n.respond(client_mac)
                if phase == 'bind':
                    # Explicit authentication failure revokes the media key.
                    try:
                        auth.receive(envelope(1, dict(deviceId=client_id)))
                    except AuthError:
                        pass
                    else:
                        raise AssertionError('repeated identity accepted')
                    assert auth.session_key is None
                else:
                    # Finishing RFCOMM is a transport handoff, not revocation
                    # of already established TCP media. A stale auth command
                    # after close must not tear down that media either.
                    peer_cipher = Cipher(auth.session_key, 65001)
                    try:
                        auth.close()
                        try:
                            w.call(dict(op='auth', generation=auth.generation, envelope='{}'))
                        except ValueError:
                            pass
                        else:
                            raise AssertionError('closed auth generation accepted')
                        encrypted = peer_cipher.encrypt(message('GET_PARAMETER * RTSP/1.0', 9, b'his_version\r\n'))
                        sight.receive(len(encrypted).to_bytes(4, 'big') + encrypted)
                        assert b'his_version: 1.0' in peer_cipher.decrypt(sight.pending[-1][4:])
                        # DMSDP owns its established cipher after the successful
                        # RFCOMM handoff, just as HiSight does.
                        surviving = w.call(dict(op='dmsdp-heartbeat', session=control_token))
                        assert surviving['state']['negotiated']
                        dmsdp_cipher = Cipher(bytes(peer_cipher.key))
                        try:
                            request = control_text('GET_PARAMETER * DMSDP/1.0', 32)
                            wire = pack_frame(dmsdp_cipher.encrypt(request), 0xab)
                            received = w.call(dict(op='dmsdp-receive', session=control_token,
                                data=wire.hex(), now_us=123458, capture=False))
                            assert received['events'] == [Messages().feed(request)[0].metadata(),
                                dict(keepalive_received=True)]
                            assert control_packet(bytes.fromhex(surviving['heartbeat']), dmsdp_cipher).start == 'GET_PARAMETER * DMSDP/1.0'
                        finally:
                            dmsdp_cipher.close()
                    finally:
                        peer_cipher.close()
                    replacement = RustAuth(w)
                    replacement.close()
                rejected(w, dict(op='dmsdp-heartbeat', session=control_token),
                    'DMSDP survived failed or replacement authentication')
                try:
                    sight.receive(b'')
                except ValueError:
                    pass
                else:
                    raise AssertionError('revoked HiSight generation still active')
                sight.close()
                assert n.respond(client_mac) is None
                auth.close()
                n.close()
                results.append(dict(phase=phase, keys_match=True, stale_auth_revoked=True,
                    media_survives_completed_auth_channel=phase == 'auth',
                    dmsdp_authenticated_ipc=True, dmsdp_duplicate_preserves_original=True,
                    dmsdp_stale_token_rejected=True,
                    dmsdp_survives_completed_auth_channel=phase == 'auth'))
                assert identity.read_bytes() == original
            finally:
                if auth:
                    auth.close()
                if w:
                    w.close()
                if p:
                    try:
                        p.call(dict(op='close'))
                    finally:
                        p.close()
    print(json.dumps(dict(rust_private_ipc_auth='passed', cases=results,
                          identity_unchanged=True, raw_credentials_logged=False)))


def broken_ipc(binary):
    runner = json.loads(os.environ.get('HELLOCAR_RUST_RUNNER', '[]'))
    for header in [struct.pack('!I', 0), struct.pack('!I', 256 * 1024 + 1), b'\x00\x01']:
        parent, child = socket.socketpair()
        process = None
        try:
            process = subprocess.Popen([*runner, binary, 'session-worker', str(child.fileno())],
                pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child.close()
            parent.sendall(header)
            parent.shutdown(socket.SHUT_WR)
            assert process.wait(timeout=5) != 0, 'invalid private IPC accepted'
        finally:
            parent.close()
            child.close()
            if process and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    print(json.dumps(dict(rust_invalid_ipc='passed', cases=3)))


if __name__ == '__main__':
    binary = str(Path(sys.argv[1]).resolve())
    transcript(binary)
    broken_ipc(binary)
    if len(sys.argv) > 2:
        authentication(binary, str(Path(sys.argv[2]).resolve()),
                       str(Path(sys.argv[3] if len(sys.argv) > 3 else sys.argv[2]).resolve()))
