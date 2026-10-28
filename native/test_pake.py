"""Real native PAKE round trips; run in a fresh process with private temp storage."""
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests/reference'))
from hichain import Runtime, Session


def exchange(runtime, mismatch):
    left = Session(runtime, '11' * 32, '22' * 32, '012345', role=1)
    right = Session(runtime, '22' * 32, '11' * 32, '987654' if mismatch else '012345')
    codes = []
    messages = []
    try:
        code, packets = left.start()
        codes.append(code)
        queue = [(right, left, packet) for packet in packets]
        for _ in range(32):
            if not queue:
                break
            target, source, packet = queue.pop(0)
            messages.append(json.loads(packet)['message'])
            code, replies = target.receive(packet)
            codes.append(code)
            # Native INFORM_MESSAGE can elicit another INFORM_MESSAGE. The
            # transport must terminate a failed session rather than echo errors.
            if 1 in target.results:
                break
            queue.extend((source, target, reply) for reply in replies)
        else:
            raise AssertionError('unbounded PAKE packet exchange')
        print(json.dumps(dict(mismatch=mismatch, messages=messages, codes=codes,
                              left_results=left.results, right_results=right.results)))
        if mismatch:
            assert 0 not in left.results and 0 not in right.results
            assert 1 in left.results or 1 in right.results
            assert left.session_key is None and right.session_key is None
        else:
            assert 0 in left.results and 0 in right.results
            assert left.session_key and left.session_key == right.session_key
    finally:
        left.close()
        right.close()


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='hellocar-hichain-') as directory:
        runtime = Runtime(sys.argv[1], directory, 'native-self-test')
        exchange(runtime, True)
        exchange(runtime, False)
    # Each device needs an isolated HUKS store. A shared in-process store can
    # overwrite one device's private alias when importing its public peer key.
    from test_trusted import verify_trusted
    verify_trusted(sys.argv[1])
    print('native PAKE: correct PIN accepted, wrong PIN rejected, session keys match')
