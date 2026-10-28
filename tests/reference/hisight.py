"""Independent HiSight RTSP handshake; all captures stay private."""
import asyncio
import os
from pathlib import Path
import re
import time
from cipher import Cipher
from control_wire import Messages
from nearby_wire import ProtocolError
from hisight_media import receive as receive_media
from hisight_input import serve as serve_input


def message(start, sequence, body=b'', headers=None):
    if not re.fullmatch(r'[0-9]{1,9}', str(sequence)):
        raise ProtocolError('invalid HiSight sequence')
    rows = [start, 'CSeq: ' + str(sequence)]
    for name, value in (headers or {}).items():
        if any(c in name + str(value) for c in '\r\n\0'):
            raise ProtocolError('invalid HiSight header')
        rows.append(name + ': ' + str(value))
    if body:
        rows.extend(['Content-Type: text/parameters', 'Content-Length: ' + str(len(body))])
    return ('\r\n'.join(rows) + '\r\n\r\n').encode('ascii') + body


class Session:
    def __init__(self, key):
        self.cipher = Cipher(key, 65001)
        self.encrypted = False
        self.buffer = bytearray()
        self.messages = Messages('RTSP')
        self.pending = []
        self.options_sent = False
        self.target = '*'
        self.media_endpoint = None
        self.input_endpoint = None
        self.setup_sequence = None
        self.sequence = 2
        self.on_plaintext = None
        self.peer_teardown = False
        self.teardown_sequence = None
        self.teardown_acknowledged = False

    def teardown(self):
        if (not self.encrypted or not self.media_endpoint or self.peer_teardown
                or self.teardown_sequence is not None):
            return None
        self.sequence += 1
        self.teardown_sequence = self.sequence
        return self.pack(message('TEARDOWN ' + self.target + ' RTSP/1.0', self.sequence))

    def request(self, method, headers=None):
        self.sequence += 1
        self.pending.append(self.pack(message(method + ' ' + self.target + ' RTSP/1.0',
                                              self.sequence, headers=headers)))
        return self.sequence

    def pack(self, payload, plain=False):
        if self.encrypted and not plain:
            payload = self.cipher.encrypt(payload)
        return len(payload).to_bytes(4, 'big') + payload

    def initial(self):
        return self.pack(message('ANNOUNCE * RTSP/1.0', 1,
            b'encrypt_description: encrypt_list=aes128ctr;version=1\r\n'), plain=True)

    def close(self):
        self.cipher.close()

    def receive(self, data):
        self.buffer.extend(data)
        events, plaintexts = [], []
        while len(self.buffer) >= 4:
            size = int.from_bytes(self.buffer[:4], 'big')
            if not 0 < size <= 65000:
                raise ProtocolError('invalid HiSight record length')
            if len(self.buffer) < size + 4:
                break
            payload = bytes(self.buffer[4:size + 4])
            del self.buffer[:size + 4]
            if self.encrypted:
                payload = self.cipher.decrypt(payload)
            plaintexts.append(payload)
            if self.on_plaintext:
                self.on_plaintext(payload)
            head, separator, body = payload.partition(b'\r\n\r\n')
            if not separator:
                # SETUP responses from the observed source end with only one
                # CRLF; their four-byte record boundary terminates headers.
                head, separator, body = payload.rstrip(b'\r\n'), b'\r\n\r\n', b''
            # HiSight's record boundary delimits the body even when its
            # ANNOUNCE omits Content-Length. DMSDP keeps the strict parser.
            if separator:
                # The observed source also counts its Transport header as a
                # SETUP response body. HiSight's explicit record length is
                # authoritative; retain strict Content-Length for DMSDP only.
                rows = [row for row in head.split(b'\r\n')
                        if row and not row.lower().startswith(b'content-length:')]
                payload = (b'\r\n'.join(rows) + b'\r\nContent-Length: '
                           + str(len(body)).encode() + separator + body)
            decoder = Messages('RTSP')
            messages = decoder.feed(payload)
            if decoder.buffer.strip(b'\r\n'):
                raise ProtocolError('incomplete HiSight message')
            for m in messages:
                events.append(m.metadata())
                seq = m.headers.get('cseq', '')
                method = m.start.split()[0]
                if method == 'ANNOUNCE':
                    if self.encrypted or b'aes128ctr' not in m.body:
                        raise ProtocolError('unsupported HiSight encryption negotiation')
                    self.pending.append(self.pack(message('RTSP/1.0 200 OK', seq), plain=True))
                    self.encrypted = True
                    events.append(dict(hisight_encryption=True))
                elif method == 'OPTIONS':
                    self.pending.append(self.pack(message('RTSP/1.0 200 OK', seq, headers={
                        'Public': 'hisight1.0, GET_PARAMETER, SET_PARAMETER'})))
                    if not self.options_sent:
                        self.pending.append(self.pack(message('OPTIONS * RTSP/1.0', 2,
                                                              headers={'Require': 'hisight1.0'})))
                        self.options_sent = True
                elif method == 'GET_PARAMETER':
                    requested = {line.partition(b':')[0].strip().decode('ascii')
                                 for line in m.body.splitlines() if line.strip()}
                    capabilities = {
                        'his_version': '1.0',
                        'his_video_formats': ('codecs 1;fps 30;gop 30;bitrate 2000000;'
                            'vbr-min 1000000;vbr-max 3000000;dpi 160;scr-w 800;scr-h 480;width 800;height 480'),
                        'his_audio_codecs': '1',
                        'his_device_type': 'device_type 4;subtype 0;',
                        'his_uibc_capability': ('input_category_list=GENERIC;generic_cap_list='
                            'left_point_down, left_point_up, left_move, left_key_down, left_key_up;'),
                    }
                    body = ''.join(k + ': ' + v + '\r\n' for k, v in capabilities.items()
                                   if k in requested).encode('ascii')
                    self.pending.append(self.pack(message('RTSP/1.0 200 OK', seq, body)))
                    events.append(dict(capabilities_replied=True, requested=sorted(requested)))
                elif method == 'SET_PARAMETER':
                    parameters = {}
                    for line in m.body.decode('ascii').splitlines():
                        name, sep, value = line.partition(':')
                        if sep:
                            parameters[name.strip().lower()] = value.strip()
                    events.append(dict(parameter_names=sorted(parameters)))
                    self.pending.append(self.pack(message('RTSP/1.0 200 OK', seq)))
                    if 'his_presentation_url' in parameters:
                        target = parameters['his_presentation_url'].split()[0]
                        if not re.fullmatch(r'rtsp://[A-Za-z0-9.:/_?=&%-]{1,256}', target):
                            raise ProtocolError('invalid HiSight presentation URL')
                        self.target = target
                    if parameters.get('his_trigger_method') == 'SETUP':
                        self.setup_sequence = self.request('SETUP', {
                            'Transport': 'RTP/AVP/UDP;unicast;client_port=0'})
                    elif parameters.get('his_trigger_method') == 'TEARDOWN':
                        self.peer_teardown = True
                elif method == 'TEARDOWN':
                    self.pending.append(self.pack(message('RTSP/1.0 200 OK', seq)))
                    self.peer_teardown = True
                elif method == 'RTSP/1.0' and seq == str(self.teardown_sequence):
                    self.teardown_acknowledged = m.start.startswith('RTSP/1.0 200 ')
                elif method == 'RTSP/1.0' and self.setup_sequence is not None and seq == str(self.setup_sequence):
                    if not m.start.startswith('RTSP/1.0 200 '):
                        raise ProtocolError('HiSight setup refused')
                    ports = re.search(r'(?:^|;)server_port=([0-9]+)', m.headers.get('transport', ''))
                    if not ports or not 1 <= int(ports[1]) <= 65535:
                        raise ProtocolError('missing HiSight media port')
                    self.media_endpoint = int(ports[1])
                    remote = re.search(r'(?:^|;)remotectl_port=([0-9]+)', m.headers.get('transport', ''))
                    if remote and 1 <= int(remote[1]) <= 65535:
                        self.input_endpoint = int(remote[1])
                    events.append(dict(media_port=self.media_endpoint))
        return events, plaintexts


async def graceful_close(sock, session, log, timeout=1.0):
    """Finish RTSP while the authenticated transport and media are still alive."""
    loop = asyncio.get_running_loop()
    try:
        record = session.teardown()
        if record is None:
            return
        async with asyncio.timeout(timeout):
            await loop.sock_sendall(sock, record)
            log('hisight_teardown_sent')
            received = 0
            while not session.teardown_acknowledged and not session.peer_teardown and received < 65004:
                data = await loop.sock_recv(sock, min(4096, 65004 - received))
                if not data:
                    break
                received += len(data)
                session.receive(data)
                for reply in session.pending:
                    await loop.sock_sendall(sock, reply)
                session.pending.clear()
            log('hisight_teardown_done', acknowledged=session.teardown_acknowledged,
                peer_teardown=session.peer_teardown)
    except (OSError, ProtocolError, UnicodeError, ValueError, RuntimeError, asyncio.TimeoutError) as error:
        log('hisight_teardown_stopped', error=type(error).__name__)


async def receive(sock, key, capture_dir, log, sink=None, continuous=False,
                  rust_worker=None, auth_generation=None):
    if rust_worker:
        from rust_session import HiSightSession
        session = HiSightSession(rust_worker, auth_generation)
        log('rust_hisight_ready')
    else:
        session = Session(key)
    raw = plain = None
    loop = asyncio.get_running_loop()
    total = 0
    capture_limit = 1024 * 1024
    media_task = None
    pending_read = None
    media_writer = None
    input_writer = None
    input_task = None
    try:
        if sink:
            sink.video_start()
        if capture_dir:
            root = Path(capture_dir) / ('hisight-' + str(time.time_ns()))
            raw = os.fdopen(os.open(str(root) + '.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
            plain = os.fdopen(os.open(str(root) + '.plain', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
            def save_plaintext(payload):
                record = len(payload).to_bytes(4, 'big') + payload
                if plain.tell() + len(record) <= capture_limit:
                    plain.write(record)
                    plain.flush()
            session.on_plaintext = save_plaintext
        await loop.sock_sendall(sock, session.initial())
        log('hisight_announce_sent')
        while continuous or total < capture_limit:
            pending_read = asyncio.create_task(loop.sock_recv(sock, 4096 if continuous else min(4096, capture_limit - total)))
            watched = [pending_read] + [task for task in (media_task, input_task) if task is not None]
            done, _ = await asyncio.wait(watched, return_when=asyncio.FIRST_COMPLETED)
            # Media/input EOF wins even when a peer floods readable RTSP data.
            if any(task in done for task in (media_task, input_task) if task is not None):
                log('hisight_transport_ended')
                break
            data = pending_read.result()
            pending_read = None
            if not data:
                break
            total += len(data)
            if raw and raw.tell() < capture_limit:
                raw.write(data[:capture_limit - raw.tell()]); raw.flush()
            events, plaintexts = session.receive(data)
            for event in events:
                log('hisight_message', **event)
            if session.media_endpoint and media_task is None:
                peer = sock.getpeername()[0]
                reader, media_writer = await asyncio.wait_for(asyncio.open_connection(
                    peer, session.media_endpoint, local_addr=(sock.getsockname()[0], 0)), 5)
                log('hisight_media_connected', port=session.media_endpoint)
                media_task = asyncio.create_task(receive_media(reader, key, capture_dir, log, sink))
                if session.input_endpoint:
                    _, input_writer = await asyncio.wait_for(asyncio.open_connection(
                        peer, session.input_endpoint, local_addr=(sock.getsockname()[0], 0)), 5)
                    log('hisight_input_connected', port=session.input_endpoint)
                    if sink:
                        input_task = asyncio.create_task(sink.input(input_writer, key))
                    elif capture_dir:
                        input_task = asyncio.create_task(serve_input(input_writer, key, capture_dir, log))
                session.request('PLAY', {'Transport': 'RTP/AVP/UDP;unicast;client_port=0'})
            for reply in session.pending:
                await asyncio.wait_for(loop.sock_sendall(sock, reply), 2)
            session.pending.clear()
            if session.peer_teardown:
                break
    except ProtocolError as error:
        log('hisight_parse_stopped', reason=str(error))
    finally:
        if sink:
            sink.video_stop()
        if pending_read:
            pending_read.cancel()
            await asyncio.gather(pending_read, return_exceptions=True)
        await graceful_close(sock, session, log)
        if input_task:
            input_task.cancel()
            await asyncio.gather(input_task, return_exceptions=True)
        if media_task:
            media_task.cancel()
            await asyncio.gather(media_task, return_exceptions=True)
        if media_writer:
            media_writer.close()
            try:
                await asyncio.wait_for(media_writer.wait_closed(), 1)
            except (OSError, asyncio.TimeoutError):
                pass
        if input_writer:
            input_writer.close()
            try:
                await asyncio.wait_for(input_writer.wait_closed(), 1)
            except (OSError, asyncio.TimeoutError):
                pass
        session.close()
        for stream in (raw, plain):
            if stream:
                stream.close()
        log('hisight_closed', bytes=total)
