"""Synthetic radio contracts and a private mock BlueZ bus; no hardware touched."""
import argparse
import array
import ast
import asyncio
import importlib.util
import json
import ipaddress
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests/reference'))
spec = importlib.util.spec_from_file_location('codec', ROOT / 'tools/test-hicar-rust.py')
codec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(codec)

ADAPTER = '/org/bluez/hci0'
CONTROL = '/org/hellocar/hicar/profile'
BUSINESS = '/org/hellocar/hicar/business'
ADVERTISEMENT = '/org/hellocar/hicar/advertisement'
AGENT = '/org/hellocar/hicar/agent'
FE35 = '0000fe35-0000-1000-8000-00805f9b34fb'
FE36 = '0000fe36-0000-1000-8000-00805f9b34fb'
PEERS = [ADAPTER + '/dev_02_00_00_00_00_%02X' % i for i in range(1, 5)]


def contracts(binary):
    # Use the existing Python reference without importing its real D-Bus stack;
    # contracts-only also runs on ARM QEMU with no Python bus dependency.
    source=ast.parse((ROOT/'tests/reference/radio_reference.py').read_text(encoding='utf8'))
    source.body=[n for n in source.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))
                 and n.name in ('normalize_peer','PeerSelection','beacon')]
    reference={'time':time,'log':lambda *args,**kwargs:None}
    exec(compile(source,'radio-python-reference','exec'),reference)
    PeerSelection,beacon=reference['PeerSelection'],reference['beacon']
    process = codec.Process([*json.loads(os.environ.get('HELLOCAR_RUST_RUNNER', '[]')), binary, 'codec'])
    cases = 0
    try:
        for selected in (None, PEERS[0]):
            for excluded in ([], ['02:00:00:00:00:01']):
                config = dict(model='00040A00', sequence=7, network=False, manage_controller=False,
                    pair_seconds=10 if selected is None else 0,
                    peer='02:00:00:00:00:01' if selected else None, exclude_peers=excluded)
                requests = [dict(device=p, select=selecting, now_ms=now) for p, selecting, now in [
                    (PEERS[0], False, 0), (PEERS[1], False, 0), (PEERS[2], True, 1),
                    (PEERS[1], True, 2), (PEERS[2], False, 10000),
                    ('/org/bluez/hci1/dev_02_00_00_00_00_03', True, 1),
                    (ADAPTER+'/dev_02_00_00_00_00_0a', True, 1),
                    (ADAPTER+'/dev_02_00_00_00_00_03/extra', True, 1)]]
                current = [0]
                reference = PeerSelection(ADAPTER, selected, config['pair_seconds'],
                    clock=lambda: current[0], exclude_peers=excluded)
                expected = []
                for request in requests:
                    current[0] = request['now_ms']/1000
                    expected.append(reference.allows(request['device'], request['select']))
                actual = process.call(dict(op='radio-contract', config=config, requests=requests))
                assert actual.get('ok'), 'radio contract rejected valid configuration'
                value = actual['result']
                assert value['allowed'] == expected and value['selected'] == reference.selected
                assert value['beacon'] == beacon(config['model'], config['sequence']).hex()
                assert value['profile_channels'] == [23, 24]
                cases += 1
        for changes in [dict(interface='end0', network=True), dict(model='not-hex!'),
                        dict(peer=None, pair_seconds=0), dict(channel=30),
                        dict(exclude_peers=['02:00:00:00:00: 1']), dict(pair_seconds=121)]:
            config = dict(model='00040A00', peer='02:00:00:00:00:01', network=False,
                          manage_controller=False)
            config.update(changes)
            assert process.call(dict(op='radio-contract', config=config, requests=[])).get('ok') is False
            cases += 1
        addresses=[dict(ifname='end0',addr_info=[dict(local='192.168.77.2'),dict(local='fe80::1')]),
                   dict(ifname='wlxtest',addr_info=[dict(local='192.168.0.2'),dict(local='fe80::2')])]
        def row(ip,port=22,state='01'):
            packed=ipaddress.ip_address(ip).packed
            raw=''.join('%08X'%int.from_bytes(packed[i:i+4],sys.byteorder) for i in range(0,len(packed),4))
            return ' 0: %s:%04X 00000000:0000 %s rest\n'%(raw,port,state)
        for tcp,tcp6,blocked in [('', '', False), (row('192.168.77.2'),' ',False),
            (row('192.168.0.2'),'',True), ('',row('fe80::2'),True),
            ('',row('fe80::1'),False),('',row('::ffff:192.168.0.2'),True),
            (row('192.168.0.2',state='0A'),'',False),(row('192.168.0.2',port=80),'',False)]:
            actual=process.call(dict(op='radio-contract',config=dict(model='00040A00',
                network=False,peer='02:00:00:00:00:01'),requests=[],addresses=addresses,
                interface='wlxtest',tcp=tcp,tcp6=tcp6))
            assert actual.get('ok') and actual['result']['ssh_blocked'] is blocked
            cases+=1
    finally:
        process.close()
    print(json.dumps(dict(rust_radio_contracts='passed', cases=cases)))


class Channel:
    def __init__(self, sock):
        self.socket = sock
        self.socket.settimeout(10)
        self.events = []
        self.next = 0

    def send(self, value):
        self.socket.sendall(json.dumps(value).encode())

    def receive(self):
        data, ancillary, flags, _ = self.socket.recvmsg(65536, socket.CMSG_SPACE(16))
        if not data:
            raise AssertionError('radio worker closed private IPC')
        descriptors = []
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array('i'); values.frombytes(payload[:len(payload)//values.itemsize*values.itemsize])
                descriptors.extend(values)
        try:
            assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            value = json.loads(data)
            return value, descriptors
        except BaseException:
            for descriptor in descriptors: os.close(descriptor)
            raise

    def call(self, op, **fields):
        self.next += 1
        self.send(dict(op=op, id=self.next, **fields))
        while True:
            value, descriptors = self.receive()
            if 'event' in value:
                self.events.append((value, descriptors)); continue
            for descriptor in descriptors: os.close(descriptor)
            assert value.get('id') == self.next and value.get('ok'), 'radio command failed'
            return value

    def close(self):
        for _, descriptors in self.events:
            for descriptor in descriptors: os.close(descriptor)
        self.events.clear()
        self.socket.close()


async def mock_bus(binary):
    from dbus_next import Message, MessageType, Variant, DBusError
    from dbus_next.aio import MessageBus
    from dbus_next.service import ServiceInterface, method, dbus_property
    from dbus_next.constants import PropertyAccess
    NM='/org/freedesktop/NetworkManager'
    NM_DEVICE=NM+'/Devices/7'
    NM_OLD=NM+'/Settings/8'
    NM_NEW=NM+'/Settings/9'
    NM_ACTIVE=NM+'/ActiveConnection/8'
    ip_state = None

    class NetworkManager(ServiceInterface):
        def __init__(self):
            super().__init__('org.freedesktop.NetworkManager');self.activated=[]
        @method()
        def GetDeviceByIpIface(self, interface:'s')->'o':
            assert interface=='lo';return NM_DEVICE
        @method()
        def ActivateConnection(self, connection:'o', device:'o', specific:'o')->'o':
            assert connection in (NM_OLD,NM_NEW) and device==NM_DEVICE and specific=='/'
            if connection == NM_NEW:
                ip_state.write_text(json.dumps(dict(polls=0)))
            self.activated.append(connection);return NM+'/ActiveConnection/9'

    class Device(ServiceInterface):
        def __init__(self):
            super().__init__('org.freedesktop.NetworkManager.Device');self.disconnected=False
        @dbus_property(access=PropertyAccess.READ)
        def ActiveConnection(self)->'o': return NM_ACTIVE
        @method()
        def Disconnect(self): self.disconnected=True

    class ActiveConnection(ServiceInterface):
        def __init__(self):super().__init__('org.freedesktop.NetworkManager.Connection.Active')
        @dbus_property(access=PropertyAccess.READ)
        def Connection(self)->'o':return NM_OLD

    class Settings(ServiceInterface):
        def __init__(self):
            super().__init__('org.freedesktop.NetworkManager.Settings');self.settings=None
        @method()
        def AddConnectionUnsaved(self, settings:'a{sa{sv}}')->'o':
            assert settings['connection']['autoconnect'].value is False
            assert settings['connection']['type'].value=='802-11-wireless'
            assert settings['connection']['interface-name'].value=='lo'
            assert len(settings['connection']['uuid'].value)==36
            assert bytes(settings['802-11-wireless']['ssid'].value)==b'HelloCar'
            assert settings['802-11-wireless']['mode'].value=='ap'
            assert settings['802-11-wireless']['channel'].value==149
            assert settings['802-11-wireless-security']['proto'].value==['rsn']
            assert len(settings['802-11-wireless-security']['psk'].value)==32
            assert settings['ipv4']['method'].value=='shared'
            assert settings['ipv4']['address-data'].value[0]['address'].value=='192.168.49.1'
            assert settings['ipv6']['method'].value=='disabled'
            self.settings=settings;return NM_NEW

    class Connection(ServiceInterface):
        def __init__(self):
            super().__init__('org.freedesktop.NetworkManager.Settings.Connection');self.deleted=False
        @method()
        def Delete(self):self.deleted=True

    class Adapter(ServiceInterface):
        def __init__(self): super().__init__('org.bluez.Adapter1')
        @dbus_property(access=PropertyAccess.READ)
        def Powered(self) -> 'b': return True
        @dbus_property(access=PropertyAccess.READ)
        def Address(self) -> 's': return '02:11:22:33:44:55'

    class AgentManager(ServiceInterface):
        def __init__(self):
            super().__init__('org.bluez.AgentManager1'); self.registered = None; self.unregistered = False
        @method()
        def RegisterAgent(self, path: 'o', capability: 's'):
            assert path == AGENT and capability == 'NoInputNoOutput'; self.registered = path
        @method()
        def RequestDefaultAgent(self, path: 'o'):
            assert path == self.registered
        @method()
        def UnregisterAgent(self, path: 'o'):
            assert path == self.registered; self.unregistered = True

    class ProfileManager(ServiceInterface):
        def __init__(self):
            super().__init__('org.bluez.ProfileManager1'); self.registered = {}; self.unregistered = []
        @method()
        def RegisterProfile(self, path: 'o', uuid: 's', options: 'a{sv}'):
            expected = 23 if path == CONTROL else 24
            assert path in (CONTROL, BUSINESS) and uuid == (FE35 if path == CONTROL else FE36)
            assert options['Channel'].value == expected
            assert options['RequireAuthentication'].value is False and options['RequireAuthorization'].value is False
            assert 'NearbyServerSocket' in options['ServiceRecord'].value
            self.registered[path] = options
        @method()
        def UnregisterProfile(self, path: 'o'):
            assert path in self.registered; self.unregistered.append(path)

    class AdvertisingManager(ServiceInterface):
        def __init__(self, bus):
            super().__init__('org.bluez.LEAdvertisingManager1'); self.bus=bus; self.owner=None; self.unregistered=False
        # This is deliberately asynchronous: it calls back into the worker
        # before replying to RegisterAdvertisement, exposing blocking deadlocks.
        @method()
        async def RegisterAdvertisement(self, path: 'o', options: 'a{sv}'):
            assert path == ADVERTISEMENT and not options
            assert self.owner
            reply = await self.bus.call(Message(destination=self.owner, path=path,
                interface='org.freedesktop.DBus.Properties', member='GetAll',
                signature='s', body=['org.bluez.LEAdvertisement1']))
            assert reply.message_type == MessageType.METHOD_RETURN
            props = reply.body[0]
            assert props['Type'].value == 'peripheral' and props['LocalName'].value == 'HelloCar'
            assert props['Discoverable'].value is True and props['TxPower'].value == 11
            assert bytes(props['ServiceData'].value['0000fdee-0000-1000-8000-00805f9b34fb'].value) == bytes([1,1,1,3,0,4,10,4,0,16,7])
            for name, value in [('Instance', Variant('y', 2)), ('TxPower', Variant('n', 8))]:
                reply=await self.bus.call(Message(destination=self.owner, path=path,
                    interface='org.freedesktop.DBus.Properties',member='Set',signature='ssv',
                    body=['org.bluez.LEAdvertisement1',name,value]))
                assert reply.message_type == MessageType.METHOD_RETURN
        @method()
        def UnregisterAdvertisement(self, path: 'o'):
            assert path == ADVERTISEMENT; self.unregistered=True

    with tempfile.TemporaryDirectory(prefix='hellocar-radio-bus-') as directory:
        daemon=subprocess.Popen(['dbus-daemon','--session','--nofork','--print-address=1'],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        bus=alien=None; process=None; channel=None
        try:
            address=await asyncio.wait_for(asyncio.to_thread(daemon.stdout.readline),5);assert address.startswith('unix:')
            bus=await MessageBus(bus_address=address.strip(),negotiate_unix_fd=True).connect()
            await bus.request_name('org.bluez')
            await bus.request_name('org.freedesktop.NetworkManager')
            agents=AgentManager();profiles=ProfileManager();advertisements=AdvertisingManager(bus)
            network=NetworkManager();device=Device();settings=Settings();connection=Connection()
            bus.export('/org/bluez',agents);bus.export('/org/bluez',profiles)
            bus.export(ADAPTER,Adapter());bus.export(ADAPTER,advertisements)
            bus.export(NM,network);bus.export(NM_DEVICE,device);bus.export(NM_ACTIVE,ActiveConnection())
            bus.export(NM+'/Settings',settings);bus.export(NM_NEW,connection)
            def owner(message):
                if message.message_type == MessageType.METHOD_CALL and message.member=='RegisterAdvertisement':
                    advertisements.owner=message.sender
            bus.add_message_handler(owner)
            parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            commands=Path(directory)/'commands';commands.mkdir()
            command_log=Path(directory)/'commands.jsonl'
            ip_state=Path(directory)/'ip-state.json'
            command_source='#!'+sys.executable+'\n'+'''import json,os,sys
from pathlib import Path
with Path(os.environ['HELLOCAR_RADIO_COMMAND_LOG']).open('a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')
if Path(sys.argv[0]).name=='ip':
    assert sys.argv[1:]==['-j','address']
    state_path=Path(os.environ['HELLOCAR_RADIO_IP_STATE'])
    addresses=[dict(ifname='lo',addr_info=[])]
    if state_path.exists():
        state=json.loads(state_path.read_text());state['polls']+=1
        state_path.write_text(json.dumps(state))
        if os.environ.get('HELLOCAR_RADIO_DELAY_IP_FOREVER')=='1':
            pass
        elif state['polls']==1:
            addresses.append(dict(ifname='other0',addr_info=[dict(family='inet',local='192.168.49.1',prefixlen=24)]))
        else:
            addresses[0]['addr_info']=[dict(family='inet',local='192.168.49.1',prefixlen=16 if state['polls']==2 else 24)]
    print(json.dumps(addresses))
else:
    assert sys.argv[1:] in (['reg','set','CN'],['dev','lo','info'])
    if sys.argv[1:]==['dev','lo','info']:print('type AP\\nchannel 149 (5745 MHz)')
'''
            for name in ('ip','iw'):
                executable=commands/name;executable.write_text(command_source);executable.chmod(0o700)
            env=dict(os.environ,DBUS_SYSTEM_BUS_ADDRESS=address.strip(),
                PATH=str(commands)+os.pathsep+os.environ.get('PATH',''),HELLOCAR_RADIO_COMMAND_LOG=str(command_log),
                HELLOCAR_RADIO_IP_STATE=str(ip_state))
            process=subprocess.Popen([*json.loads(os.environ.get('HELLOCAR_RUST_RUNNER','[]')),
                binary,'radio-worker',str(child.fileno())],pass_fds=(child.fileno(),),
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
            child.close();channel=Channel(parent)
            channel.send(dict(id=0,model='00040A00',sequence=7,network=True,interface='lo',manage_controller=False,
                pair_seconds=120,exclude_peers=['02:00:00:00:00:01']))
            ready,fds=await asyncio.to_thread(channel.receive)
            assert ready['ok'] and ready['ready'] and not fds
            assert json.loads(ip_state.read_text())['polls'] >= 3, 'readiness must await target IPv4 /24 despite a pre-existing 5 GHz AP'
            assert ready['address']=='02:11:22:33:44:55'
            assert ready['offer']['ssid']=='HelloCar' and ready['offer']['frequency']==5745
            assert ready['offer']['password']==settings.settings['802-11-wireless-security']['psk'].value
            assert ready['offer']['password'] not in command_log.read_text()
            await asyncio.to_thread(channel.call,'activate')
            assert advertisements.owner and len(profiles.registered)==2

            async def call(path, interface, member, signature='', body=(), fds=(), source=None):
                return await (source or bus).call(Message(destination=advertisements.owner,path=path,
                    interface=interface,member=member,signature=signature,body=list(body),unix_fds=list(fds)))
            # Confirmation validates candidates but cannot claim one.
            reply=await call(AGENT,'org.bluez.Agent1','RequestConfirmation','ou',[PEERS[0],123456])
            assert reply.message_type==MessageType.ERROR
            reply=await call(AGENT,'org.bluez.Agent1','RequestConfirmation','ou',[PEERS[1],123456])
            assert reply.message_type==MessageType.METHOD_RETURN
            reply=await call(AGENT,'org.bluez.Agent1','AuthorizeService','os',[PEERS[1],'0000110b-0000-1000-8000-00805f9b34fb'])
            assert reply.message_type==MessageType.ERROR
            # An unprivileged bus connection cannot forge BlueZ callbacks.
            alien=await MessageBus(bus_address=address.strip()).connect()
            reply=await call(AGENT,'org.bluez.Agent1','RequestAuthorization','o',[PEERS[1]],source=alien)
            assert reply.message_type==MessageType.ERROR
            one,two=socket.socketpair()
            try:
                reply=await call(CONTROL,'org.bluez.Profile1','NewConnection','oha{sv}',[PEERS[1],0,{}],[one.fileno()])
                assert reply.message_type==MessageType.METHOD_RETURN
                event,received=await asyncio.to_thread(channel.receive)
                assert event['event']=='rfcomm' and event['stream']=='control' and len(received)==1
                adopted=socket.socket(fileno=received[0]);adopted.settimeout(2)
                try:
                    two.sendall(b'synthetic-nearby-frame');assert adopted.recv(64)==b'synthetic-nearby-frame'
                finally:adopted.close()
                # FE36 shares the same sticky selection and rejects others.
                reply=await call(BUSINESS,'org.bluez.Profile1','NewConnection','oha{sv}',[PEERS[2],0,{}],[one.fileno()])
                assert reply.message_type==MessageType.ERROR
                reply=await call(CONTROL,'org.bluez.Profile1','NewConnection','oha{sv}',[PEERS[1],0,{}],[one.fileno()])
                assert reply.message_type==MessageType.ERROR
                await asyncio.to_thread(channel.call,'release',stream='control',device=PEERS[1])
                reply=await call(BUSINESS,'org.bluez.Profile1','NewConnection','oha{sv}',[PEERS[1],0,{}],[one.fileno()])
                assert reply.message_type==MessageType.METHOD_RETURN
                event,received=await asyncio.to_thread(channel.receive)
                assert event['stream']=='business' and len(received)==1
                for fd in received:os.close(fd)
            finally:one.close();two.close()
            process.send_signal(signal.SIGTERM)
            assert (await asyncio.to_thread(channel.call,'status'))['active']
            await asyncio.to_thread(channel.call,'close')
            assert await asyncio.to_thread(process.wait,8)==0
            assert agents.unregistered and advertisements.unregistered and set(profiles.unregistered)=={CONTROL,BUSINESS}
            assert device.disconnected and connection.deleted and network.activated==[NM_NEW,NM_OLD]
            assert process.stdout.read()==b'' and process.stderr.read()==b''
            process.stdout.close();process.stderr.close();channel.close();channel=None
            # Parent death closes the private descriptor and must perform the
            # same restoration even without an explicit close command.
            parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            process=subprocess.Popen([*json.loads(os.environ.get('HELLOCAR_RUST_RUNNER','[]')),
                binary,'radio-worker',str(child.fileno())],pass_fds=(child.fileno(),),
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
            child.close();channel=Channel(parent)
            channel.send(dict(id=0,model='00040A00',sequence=7,network=False,
                manage_controller=False,peer='02:00:00:00:00:02'))
            ready,fds=await asyncio.to_thread(channel.receive);assert ready['ok'] and not fds
            await asyncio.to_thread(channel.call,'activate')
            previous=len(profiles.unregistered)
            channel.close();channel=None
            assert await asyncio.to_thread(process.wait,8)==0
            assert len(profiles.unregistered)==previous+2
            assert process.stdout.read()==b'' and process.stderr.read()==b''
            process.stdout.close();process.stderr.close()
            # Cancellation while NM is activated but its IPv4 never arrives
            # must restore networking without waiting for the 12s IP deadline.
            for explicit_close in (True,False):
                ip_state.unlink(missing_ok=True)
                network.activated.clear();connection.deleted=False;device.disconnected=False
                parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
                cancelled_env=dict(env,HELLOCAR_RADIO_DELAY_IP_FOREVER='1')
                process=subprocess.Popen([*json.loads(os.environ.get('HELLOCAR_RUST_RUNNER','[]')),
                    binary,'radio-worker',str(child.fileno())],pass_fds=(child.fileno(),),
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=cancelled_env)
                child.close();channel=Channel(parent)
                channel.send(dict(id=0,model='00040A00',sequence=7,network=True,interface='lo',
                    manage_controller=False,peer='02:00:00:00:00:02'))
                deadline=asyncio.get_running_loop().time()+6
                while True:
                    try:
                        polls=json.loads(ip_state.read_text())['polls']
                    except (FileNotFoundError,json.JSONDecodeError):
                        polls=0
                    if polls>=2:
                        break
                    assert process.poll() is None, 'radio exited before delayed-IP cancellation fixture'
                    assert asyncio.get_running_loop().time()<deadline, 'radio did not reach delayed-IP wait'
                    await asyncio.sleep(.02)
                cancelled_at=asyncio.get_running_loop().time()
                if explicit_close:
                    reply=await asyncio.to_thread(channel.call,'close')
                    assert reply['closed'] and connection.deleted and network.activated==[NM_NEW,NM_OLD]
                else:
                    channel.close();channel=None
                assert await asyncio.to_thread(process.wait,7)==0
                assert asyncio.get_running_loop().time()-cancelled_at<7
                assert connection.deleted and device.disconnected and network.activated==[NM_NEW,NM_OLD]
                assert process.stdout.read()==b'' and process.stderr.read()==b''
                process.stdout.close();process.stderr.close()
                if channel:channel.close();channel=None
        finally:
            if channel:channel.close()
            if process and process.poll() is None:process.kill();process.wait(timeout=3)
            if process:
                if process.stdout:process.stdout.close()
                if process.stderr:process.stderr.close()
            if alien:alien.disconnect()
            if bus:bus.disconnect()
            daemon.terminate()
            try:daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=3)
            if daemon.stdout:daemon.stdout.close()
    print(json.dumps(dict(rust_radio_mock_bus='passed',hardware_accessed=False,
        callback_dispatch_during_registration=True,scm_rights=True,peer_selection=True,
        unsaved_network_settings=True,network_restored=True,credentials_absent_from_argv=True,
        delayed_ipv4_readiness=True,no_ethernet_dependency=True,
        cleanup=True,parent_eof_cleanup=True,startup_close_cleanup=True,startup_eof_cleanup=True)))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary');parser.add_argument('--contracts-only',action='store_true')
    options=parser.parse_args();binary=str(Path(options.binary).resolve())
    contracts(binary)
    if not options.contracts_only:asyncio.run(mock_bus(binary))
