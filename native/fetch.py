"""Fetch pinned public sources into an isolated build directory, never the checkout."""
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
lock = json.loads(Path(__file__).with_name('sources.json').read_text())
for name, source in lock.items():
    directory = root / name
    if directory.exists():
        revision = subprocess.check_output(['git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip()
        if revision != source['commit']:
            raise SystemExit(f'{name}: existing source directory has a different revision')
        continue
    directory.mkdir(parents=True)
    for args in (['init', str(directory)],
                 ['-C', str(directory), 'remote', 'add', 'origin', source['repository']],
                 ['-C', str(directory), 'fetch', '--depth', '1', 'origin', source['commit']],
                 ['-C', str(directory), 'checkout', '--detach', 'FETCH_HEAD']):
        subprocess.run(['git', *args], check=True)
