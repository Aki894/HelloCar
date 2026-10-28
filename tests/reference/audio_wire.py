"""HarmonyOS 4.2 Simple speaker control; media cipher is negotiated in SETUP."""
import re
from nearby_wire import ProtocolError


class Speaker:
    def __init__(self):
        self.ports = None
        self.session_id = None
        self.sequence = 0
        self.setup_sequence = None
        self.pending = []
        self.format = None
        self.ready = False
        self.remote = None

    def notify(self, name):
        event = {'audio_'+name: True, 'service': 'speaker1', 'modem': False}
        if self.remote is not None:
            event['port'] = self.remote
        if self.session_id is not None:
            event['session'] = self.session_id
        return event

    def request(self, method, encode, extra=None):
        self.sequence += 1
        fields = dict(ServiceID='speaker1', ServiceType=3,
                      DataSessionID=self.session_id, CSeq=self.sequence)
        fields.update(extra or {})
        return encode(method+' * DMSDP/1.0', fields)

    def teardown(self, encode):
        if self.session_id is None:
            return None
        record = self.request('TEARDOWN', encode)
        self.session_id = None
        self.ready = False
        self.remote = None
        return record

    def receive(self, message, encode):
        headers = message.headers
        if headers.get('serviceid') != 'speaker1':
            return None
        if headers.get('servicetype') != '3':
            raise ProtocolError('unsupported speaker transport type')
        sequence = headers.get('cseq', '')
        if not re.fullmatch(r'[0-9]{1,9}', sequence):
            raise ProtocolError('invalid speaker sequence')
        session = headers.get('datasessionid', '')
        if not re.fullmatch(r'[0-9]{1,10}', session) or int(session) > 0x7fffffff:
            raise ProtocolError('invalid speaker session')
        session = int(session)
        events = []

        def acknowledge():
            self.pending.append(encode('DMSDP/1.0 200 OK', dict(ServiceID='speaker1',
                ServiceType=3, DataSessionID=session, CSeq=sequence)))

        trigger = re.fullmatch(rb'msdp_trigger_method:\s*([A-Z]+)\s*', message.body)
        if trigger:
            if not message.start.startswith('SET_PARAMETER '):
                raise ProtocolError('speaker trigger outside SET_PARAMETER')
            if trigger[1] == b'OPTIONS':
                if (not self.ports or not 1 <= self.ports[0] <= 65535 or self.ports[1] != -1
                        or headers.get('simple') != '1' or not session):
                    raise ProtocolError('unsupported speaker setup mode')
                if session == self.session_id:
                    return []
                self.session_id, self.ready, self.format = session, False, None
                self.remote = None
                self.pending.append(self.request('SETUP', encode, dict(
                    Transport='RTP/AVP/UDP;unicast;client_port=%d--1' % self.ports[0],
                    Simple=1, CryptoVer=1, CryptoAbility=222, CryptoAlg='aes128-ctr',
                    Fillp=0, TCP=0, Codec=0)))
                self.setup_sequence = self.sequence
                events.append(self.notify("setup_sent"))
            elif trigger[1] == b'TEARDOWN':
                if session == self.session_id:
                    record = self.teardown(encode)
                    if record:
                        self.pending.append(record)
                    events.append(self.notify("stopped"))
            elif trigger[1] == b'CLOSE':
                if session == self.session_id:
                    events.append(self.notify("stopped"))
                    self.session_id, self.ready, self.remote = None, False, None
            else:
                raise ProtocolError('unsupported speaker trigger')
        elif message.start.startswith('DMSDP/1.0 '):
            if session != self.session_id or int(sequence) != self.setup_sequence:
                return []
            if not message.start.startswith('DMSDP/1.0 200 '):
                raise ProtocolError('speaker setup refused')
            transport = re.fullmatch(r'RTP/AVP/UDP;unicast;client_port=([0-9]+)--1;server_port=([0-9]+)--1',
                                     headers.get('transport', ''))
            if (not transport or int(transport[1]) != self.ports[0]
                    or not 1 <= int(transport[2]) <= 65535):
                raise ProtocolError('invalid speaker server endpoint')
            self.remote = int(transport[2])
            self.ready = True
            events.append(self.notify("ready"))
        elif session != self.session_id:
            raise ProtocolError('speaker session mismatch')
        elif message.start.startswith('SET_PARAMETER '):
            parameters = headers.get('audioparameter', '')
            fields = re.fullmatch(r'SampleRate=(48000|44100|32000|24000|16000|8000);Format=16;ChannelNum=([12]);Codec=0',
                                  parameters)
            if not fields or message.body:
                raise ProtocolError('unsupported speaker audio parameters')
            self.format = dict(codec='aac-adts', rate=int(fields[1]), channels=int(fields[2]), pcm_bits=16)
            acknowledge()
            events.append(dict(audio_negotiated=True, **self.format))
        elif message.start.startswith('TEARDOWN '):
            acknowledge()
            events.append(self.notify("stopped"))
            self.session_id, self.ready, self.remote = None, False, None
        elif message.start.startswith('GET_PARAMETER ') and not message.body:
            acknowledge()
        else:
            raise ProtocolError('unsupported speaker request')
        return events
