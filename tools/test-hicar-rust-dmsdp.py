"""Synthetic DMSDP/speaker state differential tests; no real identities or media."""
import importlib.util
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests/reference'))
from cipher import Cipher
from control_wire import Session, Decoder, Messages, pack_frame
from nearby_wire import pack_uint, read_uint

spec = importlib.util.spec_from_file_location('codec', ROOT / 'tools/test-hicar-rust.py')
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)


def message(start, headers, body=b''):
    rows = [start] + [str(k)+': '+str(v) for k,v in headers.items()]
    if body:rows += ['Content-Length: '+str(len(body))]
    return ('\r\n'.join(rows)+'\r\n\r\n').encode('ascii')+body


def business(module, command, tail):
    body = pack_uint(command)+tail
    return b'$'+module.to_bytes(4,'big')+b'\xff'*4+len(body).to_bytes(2,'big')+body


def normalize(packet, cipher):
    frames=Decoder().feed(packet)
    assert len(frames)==1, 'invalid differential response framing'
    data=frames[0].payload
    if frames[0].marker==0xab:data=cipher.decrypt(data)
    if data.startswith(b'$'):
        assert len(data)>=11 and int.from_bytes(data[9:11],'big')==len(data)-11
        module=int.from_bytes(data[1:5],'big');kind=int.from_bytes(data[5:9],'big')
        command,pos=read_uint(data[11:])
        if module==3 and command in (101,102):body=json.loads(data[11+pos:])
        elif module==5 and command==101:
            body,end=read_uint(data[11:],pos);assert end==len(data)-11
        else:body=data[11+pos:].hex()
        return dict(binary=True,module=module,data_type=kind,command=command,body=body)
    texts=Messages().feed(data)
    assert len(texts)==1, 'invalid differential response text'
    return dict(start=texts[0].start,headers=texts[0].headers,body=texts[0].body.hex())


def python_state(session):
    speaker=session.speaker
    return dict(failed=False,negotiated=session.negotiated,device_exchanged=session.device_exchanged,
        clock=list(session.clock) if session.clock else None,media_port=session.media_port,
        heartbeat_sequence=session.heartbeat_sequence,
        speaker=None if speaker is None else dict(ports=list(speaker.ports) if speaker.ports else None,
            session_id=speaker.session_id,sequence=speaker.sequence,setup_sequence=speaker.setup_sequence,
            format=speaker.format,ready=speaker.ready))


def compare(actual, key, info, audio, steps):
    session=Session(key or None,info,audio)
    cipher=Cipher(key) if key else None
    try:
        assert actual.get('ok'), 'valid DMSDP transcript rejected'
        actual=actual['result']
        assert normalize(bytes.fromhex(actual['initial']),cipher)==normalize(session.initial(),cipher), 'DMSDP initial mismatch'
        assert len(actual['steps'])==len(steps)
        for index,(step,result) in enumerate(zip(steps,actual['steps'])):
            events=[];plaintexts=[];session.on_plaintext=plaintexts.append
            if 'ports' in step:
                session.speaker.ports=tuple(step['ports'])
            if 'receive' in step:
                with patch('control_wire.time.monotonic_ns', return_value=step.get('now_us',0)*1000):
                    events=session.receive(bytes.fromhex(step['receive']))
            heartbeat=session.heartbeat() if step.get('heartbeat') else None
            if step.get('stop_audio'):session.stop_audio()
            assert result['events']==events, 'DMSDP event mismatch at step '+str(index)
            assert result['plaintexts']==[p.hex() for p in plaintexts], 'DMSDP plaintext mismatch'
            assert [normalize(bytes.fromhex(p),cipher) for p in result['pending']]==[normalize(p,cipher) for p in session.take_pending()], 'DMSDP replies mismatch at step '+str(index)
            assert (None if result['heartbeat'] is None else normalize(bytes.fromhex(result['heartbeat']),cipher))==(None if heartbeat is None else normalize(heartbeat,cipher)), 'DMSDP heartbeat mismatch'
            assert result['state']==python_state(session), 'DMSDP state mismatch at step '+str(index)
    finally:
        session.close()
        if cipher:cipher.close()


def check(binary):
    runner=json.loads(os.environ.get('HELLOCAR_RUST_RUNNER','[]'))
    worker=codec.Process([*runner,binary,'codec'])
    key=bytes(range(16));cipher=Cipher(key)
    info=dict(deviceId='A'*64,deviceName='HelloCar 测试😀',deviceType=4,
        bluetoothMac='02:00:00:00:00:01',btName='HelloCar',localIp='192.168.49.1',
        remoteIp='192.168.49.2',port=0,properties={'2003':'00040A00','5004':True,'5014':False})
    def wire(data, encrypted=True):return pack_frame(cipher.encrypt(data),0xab) if encrypted else pack_frame(data)
    def command(method='SET_PARAMETER',sequence=1,body=b'',session=42,**fields):
        headers=dict(ServiceID='speaker1',ServiceType=3,DataSessionID=session,CSeq=sequence,**fields)
        return message(method+' * DMSDP/1.0',headers,body)
    negotiation=wire(message('SET_PARAMETER * DMSDP/1.0',dict(CSeq=7,CryptoVer=1,CryptoSwitch=222,CryptoAlg='aes128-ctr')),False)
    device=wire(business(3,101,json.dumps(dict(deviceId='synthetic-peer',businessId=7),separators=(',',':')).encode()))
    tail=[dict(ports=[40000,-1]),dict(receive=device.hex()),
        dict(receive=wire(business(3,104,(12).to_bytes(4,'big'))).hex()),
        dict(receive=wire(business(5,101,pack_uint(49000))).hex()),
        dict(receive=wire(message('SET_PARAMETER * DMSDP/1.0',dict(CSeq='0008',TimeServerPort='+41000',TimeUsHigh='-1',TimeUsLow='4_294_967_303'))).hex(),now_us=123456789),
        dict(heartbeat=True),dict(receive=wire(message('GET_PARAMETER * DMSDP/1.0',dict(CSeq='009'))).hex()),
        dict(receive=wire(command(body=b'msdp_trigger_method: OPTIONS\r\n',Simple=1)).hex()),
        dict(receive=wire(message('DMSDP/1.0 200 OK',dict(ServiceID='speaker1',ServiceType=3,DataSessionID=42,CSeq=1,
            Transport='RTP/AVP/UDP;unicast;client_port=40000--1;server_port=44000--1'))).hex()),
        dict(receive=wire(command(sequence=10,AudioParameter='SampleRate=48000;Format=16;ChannelNum=2;Codec=0')).hex()),
        dict(receive=wire(command('GET_PARAMETER',11)).hex()),
        dict(receive=wire(command(sequence=12,body=b'msdp_trigger_method: OPTIONS',Simple=1)).hex()),
        dict(receive=wire(message('DMSDP/1.0 500 NO',dict(ServiceID='speaker1',ServiceType=3,DataSessionID=42,CSeq=999))).hex()),
        dict(stop_audio=True),dict(receive=wire(command(sequence=13,body=b'msdp_trigger_method: TEARDOWN')).hex()),
        dict(receive=wire(command(sequence=14,session=43,body=b'msdp_trigger_method: OPTIONS',Simple=1)).hex()),
        dict(receive=wire(command(sequence=15,session=43,body=b'msdp_trigger_method: CLOSE')).hex()),dict(heartbeat=True)]
    count=0
    try:
        cases=[[dict(receive=negotiation[:n].hex()),dict(receive=negotiation[n:].hex()),*tail] for n in range(len(negotiation)+1)]
        cases.append([dict(receive=bytes([b]).hex()) for b in negotiation]+tail)
        cases.extend([[dict(receive=negotiation.hex()),dict(ports=[40000,-1]),
            dict(receive=device[:n].hex()),dict(receive=device[n:].hex()),*tail[2:]] for n in range(len(device)+1)])
        # Multiple small records in one read and duplicate device discovery.
        cases.append([dict(receive=negotiation.hex()),dict(ports=[40000,-1]),
            dict(receive=(device+device+wire(business(3,104,(12).to_bytes(4,'big')))).hex()),*tail[3:]])
        for steps in cases:
            result=worker.call(dict(op='dmsdp-session',key=key.hex(),device_info=info,audio=True,steps=steps))
            compare(result,key,info,True,steps);count+=1
        # Null encryption and no speaker/device identity retain legacy framing.
        null=pack_frame(message('SET_PARAMETER * DMSDP/1.0',dict(CSeq=1,CryptoVer=1,CryptoSwitch=222,CryptoAlg='null')))
        null_steps=[dict(receive=null.hex()),dict(heartbeat=True),dict(receive=pack_frame(b'opaque-encrypted',0xab).hex()),
            dict(receive=pack_frame(message('GET_PARAMETER * DMSDP/1.0',dict(CSeq=2))).hex()),dict(stop_audio=True)]
        compare(worker.call(dict(op='dmsdp-session',key='',device_info=None,audio=False,steps=null_steps)),b'',None,False,null_steps);count+=1
        short=[dict(receive=negotiation.hex()),dict(receive=device.hex()),dict(receive=wire(business(3,104,(12).to_bytes(4,'big'))).hex()),dict(heartbeat=True)]
        compare(worker.call(dict(op='dmsdp-session',key=key.hex(),device_info=info,audio=False,steps=short)),key,info,False,short);count+=1
        key32=key+bytes(range(16,32))
        compare(worker.call(dict(op='dmsdp-session',key=key32.hex(),device_info=info,audio=True,steps=[dict(receive=negotiation.hex()),*tail])),key32,info,True,[dict(receive=negotiation.hex()),*tail]);count+=1
        # mic1 is an RTP sender. The phone drives ordinary OPTIONS/crypto/SETUP/PLAY;
        # its SETUP client port is the destination, rather than our bound port.
        mic_info={**info,'properties':{**info['properties'],'5002':True}}
        def mic(method,sequence,session=73,body=b'',**extra):
            return message(method+' * DMSDP/1.0',dict(ServiceID='mic1',ServiceType=2,DataSessionID=session,CSeq=sequence,**extra),body)
        mic_trigger=mic('SET_PARAMETER',1,body=b'msdp_trigger_method: OPTIONS',Simple=1)
        mic_crypto=mic('SET_PARAMETER',11,CryptoVer=1,CryptoSwitch=222,CryptoAlg='aes128-ctr',Fillp=0,TCP=0)
        mic_format=mic('SET_PARAMETER',12,AudioParameter='SampleRate=48000;Format=16;ChannelNum=2;Codec=0')
        mic_setup=mic('SETUP',13,Transport='RTP/AVP/UDP;unicast;client_port=43000--1')
        mic_play=mic('PLAY',14)
        mic_steps=[dict(receive=negotiation.hex()),dict(ports=[40000,-1])]
        mic_steps += [dict(receive=wire(data).hex()) for data in (mic_trigger,mic_crypto,mic_format,mic_setup,mic_play,mic_play)]
        result=worker.call(dict(op='dmsdp-session',key=key.hex(),device_info=mic_info,audio=True,steps=mic_steps))
        assert result.get('ok'), 'encrypted microphone transcript rejected'
        result=result['result']['steps']
        options=normalize(bytes.fromhex(result[2]['pending'][0]),cipher)
        assert options['start']=='OPTIONS * DMSDP/1.0' and options['headers']['simple']=='0'
        assert 'transport' not in options['headers']
        crypto_ack=normalize(bytes.fromhex(result[3]['pending'][0]),cipher)
        assert crypto_ack['headers']['cryptover']=='1' and crypto_ack['headers']['cseq']=='11'
        assert result[4]['events'][-1]['audio_negotiated'] is True
        setup_ack=normalize(bytes.fromhex(result[5]['pending'][0]),cipher)
        assert setup_ack['headers']['transport']=='RTP/AVP/UDP;unicast;client_port=43000--1;server_port=40000--1'
        assert not any(e.get('microphone_ready') for e in result[5]['events'])
        assert result[6]['events'][-1]['microphone_ready'] is True and result[6]['events'][-1]['port']==43000
        assert not any(e.get('microphone_ready') for e in result[7]['events']) and len(result[7]['pending'])==1
        count+=1
        invalid=[
            [dict(receive=b'\x01\0\x01x'.hex())], [dict(receive=b'\0\0\0'.hex())],
            [dict(receive=(b'\0'+(1498).to_bytes(2,'big')).hex())],
            [dict(receive=wire(message('GET_PARAMETER * DMSDP/1.0',{'CSeq':1})).hex())],
            [dict(receive=pack_frame(b'SET_PARAMETER * DMSDP/1.0\r\nCSeq: 1\r\nCSeq: 2\r\n\r\n').hex())],
            [dict(receive=pack_frame(message('SET_PARAMETER * DMSDP/1.0',dict(CSeq=-1,CryptoVer=1,CryptoSwitch=222,CryptoAlg='aes128-ctr'))).hex())],
            [dict(receive=negotiation.hex()),dict(receive=wire(b'$'+bytes(3)).hex())],
            [dict(receive=negotiation.hex()),dict(receive=wire(business(5,101,pack_uint(0))).hex())],
            [dict(receive=negotiation.hex()),dict(receive=wire(business(3,104,(8).to_bytes(4,'big'))).hex())],
            [dict(receive=negotiation.hex()),dict(receive=wire(business(3,101,b'[]')).hex())],
            [dict(receive=negotiation.hex()),dict(receive=wire(business(3,101,b'{"deviceId":"a","deviceId":"b"}')).hex())],
            [dict(heartbeat=True)], [dict(ports=[40000,40001])],
            [dict(receive=negotiation.hex()),dict(receive=wire(command(body=b'msdp_trigger_method: OPTIONS',Simple=1)).hex())],
            [dict(receive=negotiation.hex()),dict(ports=[40000,-1]),dict(receive=wire(command(body=b'msdp_trigger_method: OPTIONS',Simple=1)).hex()),
                dict(receive=wire(command(AudioParameter='SampleRate=48000;Format=16;ChannelNum=9;Codec=0')).hex())],
        ]
        for steps in invalid:
            assert worker.call(dict(op='dmsdp-session',key=key.hex(),device_info=info,audio=True,steps=steps)).get('ok') is False, 'invalid DMSDP transcript accepted'
    finally:
        worker.close();cipher.close()
    print(json.dumps(dict(rust_dmsdp_transcripts='passed',cases=count,invalid_cases=len(invalid),synthetic_only=True)))


if __name__=='__main__':
    check(str(Path(sys.argv[1]).resolve()))
