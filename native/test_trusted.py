"""Bind two isolated devices, restart them, then verify trusted STS auth."""
import hashlib
import json
import multiprocessing as mp
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests/reference'))
from hichain import Runtime, Session


def worker(library, store, role, connection):
    own, peer = ('AB' * 32, 'CD' * 32) if role == 1 else ('CD' * 32, 'AB' * 32)
    runtime = Runtime(library, store, own)
    session = None
    try:
        while True:
            command, data = connection.recv()
            if command == 'close':
                break
            if command == 'begin':
                session = Session(runtime, own, peer, '012345', role=role,
                                  package='com.huawei.hicar', service='CarDevice')
                code, packets = ((session.start() if data == 'bind' else session.authenticate(16))
                                 if role == 1 else (0, []))
            else:
                code, packets = session.receive(data)
            key = session.session_key
            connection.send((code, packets, list(session.results),
                             hashlib.sha256(key).digest() if key else None, len(key) if key else 0))
    except Exception as error:
        connection.send(('error', type(error).__name__))
    finally:
        if session:
            session.close()
        connection.close()


def verify_trusted(library):
    context = mp.get_context('spawn')
    with tempfile.TemporaryDirectory(prefix='hellocar-trusted-') as directory:
        for phase in ('bind', 'auth'):
            peers, processes = [], []
            try:
                for role in (1, 2):
                    parent, child = context.Pipe()
                    process = context.Process(target=worker, args=(str(Path(library).resolve()),
                        str(Path(directory) / str(role)), role, child))
                    process.start(); child.close()
                    peers.append(parent); processes.append(process)
                def call(index, command, data=None):
                    peers[index].send((command, data))
                    assert peers[index].poll(30), 'native peer timed out'
                    result = peers[index].recv()
                    assert result[0] != 'error', 'native peer error: ' + str(result[1])
                    return result
                states = [None, call(1, 'begin', phase)]
                states[0] = call(0, 'begin', phase)
                queue = [(1, packet) for packet in states[0][1]]
                messages = []
                for _ in range(32):
                    if not queue:
                        break
                    target, packet = queue.pop(0)
                    messages.append(json.loads(packet)['message'])
                    states[target] = call(target, 'receive', packet)
                    assert 1 not in states[target][2], 'native auth failed: ' + str([
                        json.loads(p).get('payload', {}).get('errorCode') for p in states[target][1]])
                    queue.extend((1 - target, p) for p in states[target][1])
                assert all(0 in state[2] for state in states), 'native auth incomplete'
                assert states[0][3] == states[1][3]
                assert all(state[4] == (32 if phase == 'bind' else 16) for state in states)
                print(json.dumps(dict(isolated=True, phase=phase, messages=messages,
                                      restarted=phase == 'auth', keys_match=True)))
            finally:
                for peer in peers:
                    try:
                        peer.send(('close', None)); peer.close()
                    except (BrokenPipeError, EOFError):
                        pass
                for process in processes:
                    process.join(5)
                    if process.is_alive():
                        process.terminate(); process.join(5)


if __name__ == '__main__':
    verify_trusted(sys.argv[1])
