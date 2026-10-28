"""Synthetic differential checks against the frozen Python HiCar protocol code.

No capture, phone identity or pairing material is read. Rust stdout is a private
test pipe; failures print only the test name, never authentication packets.
"""
import argparse
import json
import os
import random
from pathlib import Path
import queue
import struct
import subprocess
import sys
import threading
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests/reference'))
import nearby_wire as nearby
import dmsdp_wire as module
import control_wire as control
from auth_wire import JsonStream, AuthError, parse_json
from audio_media import Audio, adts_frames
from audio_transport import Clock
from cipher import Cipher
from hisight_media import Depacketizer
from hisight_input import Input
from identity import Identity


class Process:
    def __init__(self, command):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, encoding='utf-8', bufsize=1)
        self.output = queue.Queue()
        def read():
            for line in self.process.stdout:
                self.output.put(line)
            self.output.put(None)
        self.thread = threading.Thread(target=read, daemon=True)
        self.thread.start()

    def call(self, request, timeout=15):
        self.process.stdin.write(json.dumps(request, ensure_ascii=True)+'\n')
        self.process.stdin.flush()
        line = self.output.get(timeout=timeout)
        if line is None:
            raise AssertionError('Rust test worker exited')
        return json.loads(line)

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=3)
        self.process.stdout.close()
        self.thread.join(1)


def check_codec(binary):
    process = Process([*json.loads(os.environ.get('HELLOCAR_RUST_RUNNER','[]')), binary, 'codec'])
    count = 0
    def check(name, request, expected):
        nonlocal count
        try:
            reference = expected() if callable(expected) else expected
            success = True
        except (ValueError, nearby.Incomplete, UnicodeError):
            reference, success = None, False
        result = process.call(request)
        assert result.get('ok') is success, 'accept/reject differs: '+name
        if success:
            assert result['result'] == reference, 'decoded output differs: '+name
        count += 1

    def framed(format_, data, chunks):
        d = {'nearby': nearby.Decoder, 'module': module.Decoder,
             'control': control.Decoder}[format_]()
        frames = []
        for part in chunks:
            frames.extend(d.feed(part))
        d.finish()
        return dict(frames=[dict(kind=f.kind if format_=='nearby' else f.module if format_=='module' else f.marker,
            flags=f.flags if format_=='nearby' else 0,
            options=f.options.hex() if format_=='nearby' else '', payload=f.payload.hex()) for f in frames])

    def json_stream(chunks):
        stream = JsonStream(); values = []
        for chunk in chunks:
            values.extend(stream.feed(chunk))
        stream.finish()
        return dict(values=values)

    def text_stream(protocol, chunks):
        d = control.Messages(protocol); values = []
        for chunk in chunks:
            values.extend(d.feed(chunk))
        if d.buffer:
            raise ValueError('incomplete text')
        return dict(messages=[dict(start=m.start, headers=m.headers, body=m.body.hex()) for m in values])

    try:
        rng = random.Random(418)
        for n in [-1, 0, 127, 128, 16384, (1<<28)-1, 1<<28, *[rng.randrange(1<<28) for _ in range(80)]]:
            check('uint', dict(op='uint',value=n), lambda n=n:dict(hex=nearby.pack_uint(n).hex()))
        for size in (0, 1, 127, 128, 4096, 65536):
            payload = bytes(rng.randrange(256) for _ in range(size))
            check('crc', dict(op='crc',data=payload.hex()), dict(crc=nearby.crc16(payload)))
            check('tlv', dict(op='tlv',tag=7,data=payload.hex()), lambda:dict(hex=nearby.pack_tlv(7,payload).hex()))
            for fmt, encoder in [('nearby',lambda:nearby.pack_frame(19,payload,1,b'\x01\x02')),
                                 ('module',lambda:module.pack(3,payload)),
                                 ('control',lambda:control.pack_frame(payload,0xab))]:
                request=dict(op='encode',format=fmt,kind=19 if fmt=='nearby' else 3 if fmt=='module' else 0xab,
                             flags=1,options='0102',payload=payload.hex())
                check('encode '+fmt, request, lambda:dict(hex=encoder().hex()))
                try: data=encoder()
                except ValueError: continue
                splits=range(len(data)+1) if len(data)<200 else sorted({0,1,3,7,len(data)//2,len(data)-1,len(data)})
                for split in splits:
                    parts=[data[:split],data[split:]]
                    check('split '+fmt,dict(op='decode',format=fmt,chunks=[p.hex() for p in parts]),
                          lambda:framed(fmt,data,parts))
                if fmt!='control':
                    for _ in range(12):
                        bad=bytearray(data);bad[rng.randrange(len(bad))]^=1
                        check('corrupt '+fmt,dict(op='decode',format=fmt,chunks=[bad.hex()]),
                              lambda:framed(fmt,bad,[bad]))
        for model,address in [('00040a00','02:00:00:00:00:01'),('00112233','12:ab:cd:ef:01:23'),('bad','02:00:00:00:00:01'),('00112233','bad')]:
            identity=Identity('ab'*32,'012345','HelloCar synthetic')
            check('persistent identity derivation',dict(op='identity',record=identity.encoded().decode(),model=model,address=address),
                  lambda:dict(wire_id=identity.for_adapter(model,address).device_id))
        for data in (b'{}{}', '{"unicode":"中文\\\"}"}{"list":[1,true,null]}'.encode(),
                     b'{"a":1,"a":2}',b'{"a":{"b":1,"b":2}}',b'{"x":NaN}',
                     b'{"x":\xff}',b'{"x":"\xff"}',b'{"a":',b'{"x":'+b'['*33+b'0'+b']'*33+b'}'):
            for split in range(len(data)+1):
                parts=[data[:split],data[split:]]
                check('JSON split',dict(op='json',chunks=[p.hex() for p in parts]),lambda:json_stream(parts))
        for protocol in ('DMSDP','RTSP'):
            for data in [f'SETUP * {protocol}/1.0\r\nCSeq: 2\r\nContent-Length: 2\r\n\r\n{{}}'.encode(),
                         f'{protocol}/1.0 200 OK\r\nCSeq: 3\r\n\r\n'.encode(),
                         f'OPTIONS * {protocol}/1.0\r\nX: 1\r\nx: 2\r\n\r\n'.encode(),
                         f'OPTIONS * {protocol}/1.0\r\nContent-Length: -1\r\n\r\n'.encode()]:
                for split in range(len(data)+1):
                    parts=[data[:split],data[split:]]
                    check('text split',dict(op='text',protocol=protocol,chunks=[p.hex() for p in parts]),lambda:text_stream(protocol,parts))
        aac=bytes.fromhex('fff14c80017ffc00000000')
        for data in (aac,aac*2,b'',aac[:-1],b'\0'*12):
            check('ADTS',dict(op='adts',data=data.hex()),lambda:dict(frames=[dict(data=f.hex(),rate=r,channels=c,samples=s) for f,r,c,s in adts_frames(data)]))
        packets=[]
        def rtp(seq,ssrc=1003):return struct.pack('!BBHII',128,96,seq,100,ssrc)+aac
        for seq,ssrc in [(65535,0x1003eb),(1,0x103eb),(0,0x43eb),(1,1003),(40,0x1103eb)]:packets.append(rtp(seq,ssrc))
        def audio():
            d=Audio();frames=[]
            for p in packets:frames.extend(d.receive(p))
            for f in frames:f['data']=f['data'].hex()
            return dict(frames=frames,lost=d.lost,duplicates=d.duplicates,packets=d.packets,samples=d.samples)
        check('RTP usage wrap gap reorder',dict(op='audio',chunks=[p.hex() for p in packets]),audio)
        for now in (1000000,900000000000):
            for offset in (-123456789,0,123456789):
                for age in (0,60000000,60000001):
                    stamp=((now+offset)*90000//1000000)&0xffffffff
                    d=Clock();d.update(offset,1000,now)
                    # The Rust API returns None for pre-boot negative time.
                    expected=d.local_rtp_time(stamp,now+age)
                    check('clock wrap/stale',dict(op='clock',timestamp=stamp,now=now+age,offset=offset,updated=now),dict(local_pts=expected))
        key=bytes(range(16));iv=bytes(reversed(range(16)));cipher=Cipher(key)
        try:
            for size in (1,16,33,1400):
                plain=bytes(rng.randrange(256) for _ in range(size))
                check('AES CTR',dict(op='cipher',key=key.hex(),iv=iv.hex(),data=plain.hex()),dict(hex=cipher.transform(plain,iv).hex()))
            for name in ('left','right','up','down','enter','back','home','play_pause'):
                for down in (False,True):
                    encoder=Input(key)
                    try:body=encoder.cipher.decrypt(encoder.key(name,down)[4:])[6:]
                    finally:encoder.cipher.close()
                    check('key',dict(op='key',name=name,down=down),dict(hex=body.hex()))
            for action in (0,1,2):
                with patch('hisight_input.time.monotonic',return_value=10):encoder=Input(key)
                try:
                    with patch('hisight_input.time.monotonic',return_value=11):packet=encoder.touch(400,240,action!=1,action==2)
                    body=encoder.cipher.decrypt(packet[4:])[6:]
                finally:encoder.cipher.close()
                check('UIBC edge',dict(op='touch',x=400,y=240,action=action,elapsed=1000),dict(hex=body.hex()))
            es=iv+cipher.transform(b'\0\0\0\1\x65synthetic',iv)
            pes=b'\0\0\1\xe0'+(len(es)+8).to_bytes(2,'big')+bytes([0x84])+bytes(7)+es
            parts=[pes[:20],pes[20:]]
            packets=[struct.pack('!BBHII',128,96|(128 if i==1 else 0),i,1234,0)+p for i,p in enumerate(parts)]
            d=Depacketizer(key)
            try:
                reference=[]
                for p in packets:
                    frame=d.receive(p)
                    if frame:reference.append(dict(kind=frame[0],timestamp=frame[1],data=frame[2].hex()))
            finally:d.cipher.close()
            check('fragmented encrypted video',dict(op='video',key=key.hex(),chunks=[p.hex() for p in packets]),dict(frames=reference))
        finally:cipher.close()
    finally:process.close()
    print(json.dumps(dict(hicar_rust_differential='passed',cases=count,synthetic_only=True)))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('binary');args=parser.parse_args()
    check_codec(str(Path(args.binary).resolve()))
