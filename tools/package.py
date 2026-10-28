"""Assemble and verify Linux receiver artifacts from CI-built inputs only."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ARCHES = {'x86_64': ('x86_64-linux-gnu', 2, 62),
          'armv7': ('arm-linux-gnueabihf', 1, 40)}
NATIVE_DEPS = [('libcrypto.so.3', 'libssl3', 'openssl'),
               ('libmbedcrypto.so.7', 'libmbedcrypto7', 'mbedtls'),
               ('libcjson.so.1', 'libcjson1', 'cjson')]


def command(*args):
    return subprocess.check_output(list(args), text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def elf(path, arch):
    _, elf_class, machine = ARCHES[arch]
    with path.open('rb') as stream:
        header = stream.read(64)
    if (len(header) < 52 or header[:4] != b'\x7fELF' or header[4] != elf_class
            or header[5] != 1 or struct.unpack_from('<H', header, 18)[0] != machine):
        raise ValueError('ELF architecture mismatch: ' + path.name)
    flags = struct.unpack_from('<I', header, 36 if elf_class == 1 else 48)[0]
    if arch == 'armv7' and flags & 0x600 != 0x400:
        raise ValueError('ARM binary must use the hard-float ABI: ' + path.name)


def rust_sources(destination):
    metadata = json.loads(command('cargo', '+1.90.0', 'metadata', '--locked',
                                  '--format-version', '1', '--manifest-path', str(ROOT / 'Cargo.toml')))
    locked = {(item['name'], item['version']): item
              for item in tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']}
    archives = destination / 'share/source/crates'
    archives.mkdir(parents=True)
    records = []
    for package in metadata['packages']:
        if not package.get('source'):
            continue
        if not package['source'].startswith('registry+'):
            raise ValueError('Only locked registry Rust dependencies are supported')
        manifest = Path(package['manifest_path'])
        identifier = package['name'] + '-' + package['version']
        archive = manifest.parents[3] / 'cache' / manifest.parents[1].name / (identifier + '.crate')
        expected = locked[(package['name'], package['version'])]['checksum']
        if digest(archive) != expected:
            raise ValueError('Rust registry source checksum mismatch: ' + identifier)
        shutil.copyfile(archive, archives / archive.name)
        notices = destination / 'share/licenses/rust' / identifier
        notices.mkdir(parents=True)
        license_files = []
        for notice in sorted(manifest.parent.iterdir()):
            if notice.is_file() and notice.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE')):
                shutil.copyfile(notice, notices / notice.name)
                license_files.append(notice.name)
        if not license_files:
            raise ValueError('Missing Rust dependency license: ' + identifier)
        records.append(dict(name=package['name'], version=package['version'],
                            license=package['license'], sha256=expected,
                            source='https://crates.io/api/v1/crates/' + package['name'] + '/' + package['version'] + '/download',
                            license_files=license_files))
    return records


def native_sources(destination, sources):
    pins = json.loads((ROOT / 'native/sources.json').read_text())
    output = destination / 'share/source/native'
    output.mkdir(parents=True)
    shutil.copyfile(ROOT / 'native/sources.json', output / 'sources.json')
    for name, source in pins.items():
        directory = sources / name
        if command('git', '-C', str(directory), 'rev-parse', 'HEAD') != source['commit']:
            raise ValueError('Native source revision mismatch: ' + name)
        if command('git', '-C', str(directory), 'status', '--porcelain', '--untracked-files=no'):
            raise ValueError('Native source has unrecorded modifications: ' + name)
        data = subprocess.check_output(['git', '-C', str(directory), 'archive', '--format=tar', 'HEAD'])
        (output / (name + '-' + source['commit'] + '.tar.gz')).write_bytes(gzip.compress(data, mtime=0))
        license_path = directory / 'LICENSE'
        if not license_path.is_file():
            raise ValueError('Missing native source license: ' + name)
        notices = destination / 'share/licenses/native'
        notices.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(license_path, notices / (name + '.txt'))
    return pins


def verify(destination):
    destination = destination.resolve()
    manifest = json.loads((destination / 'BUILD.json').read_text())
    arch = manifest['architecture']
    for relative in ['libexec/hellocar', 'lib/libhellocar_hichain.so'] + ['lib/' + name for name, _, _ in NATIVE_DEPS]:
        elf(destination / relative, arch)
    expected = {}
    for line in (destination / 'SHA256SUMS').read_text().splitlines():
        checksum, relative = line.split('  ', 1)
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts or relative in expected:
            raise ValueError('Invalid package checksum path')
        if digest(destination / path) != checksum:
            raise ValueError('Package checksum mismatch: ' + relative)
        expected[relative] = checksum
    actual = {path.relative_to(destination).as_posix() for path in destination.rglob('*')
              if path.is_file() and path != destination / 'SHA256SUMS'}
    if actual != set(expected):
        raise ValueError('Package checksum manifest is incomplete')
    forbidden = ('.apk', '.aab', '.jks', '.keystore', '.pk8', '.p7b', '.p12', '.pem', '.key', '.pcap', '.btsnoop')
    for relative in actual:
        if relative.lower().endswith(forbidden) or Path(relative).name == 'identity.json':
            raise ValueError('Private/reference artifact in runtime package')
        if {'reference', '.git', 'keys'} & set(Path(relative).parts):
            raise ValueError('Unexpected source tree in runtime package')
    print(json.dumps(dict(package=destination.name, architecture=arch, files=len(actual),
                          checksums='passed', elf_abi='passed')))


def package(options):
    arch = options.arch
    triplet = ARCHES[arch][0]
    destination = ROOT / 'dist' / ('hellocar-linux-' + arch)
    destination.mkdir(parents=True, exist_ok=False)
    for name in ('bin', 'libexec', 'lib'):
        (destination / name).mkdir()
    shutil.copyfile(ROOT / 'bin/hellocar', destination / 'bin/hellocar')
    shutil.copyfile(options.binary, destination / 'libexec/hellocar')
    shutil.copyfile(options.native, destination / 'lib/libhellocar_hichain.so')
    for executable in ('bin/hellocar', 'libexec/hellocar'):
        (destination / executable).chmod(0o755)
    dependencies = []
    for name, debian_package, notice_name in NATIVE_DEPS:
        library = Path('/usr/lib') / triplet / name
        elf(library, arch)
        shutil.copyfile(library.resolve(), destination / 'lib' / name)
        notice = Path('/usr/share/doc') / debian_package / 'copyright'
        notices = destination / 'share/licenses/runtime'
        notices.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(notice, notices / (notice_name + '.txt'))
        # Debian source version, binary version and hashes identify precisely
        # the bundled upstream/runtime code, even after a security update.
        package_arch = 'armhf' if arch == 'armv7' else 'amd64'
        info = command('dpkg-query', '-W', '-f=${Version}\t${source:Package}\t${source:Version}',
                       debian_package + ':' + package_arch).split('\t')
        dependencies.append(dict(library=name, binary_package=debian_package,
                                 binary_version=info[0], source_package=info[1], source_version=info[2],
                                 sha256=digest(destination / 'lib' / name),
                                 source_index='https://sources.debian.org/src/' + info[1] + '/' + info[2] + '/'))
    source = destination / 'share/source/hellocar'
    source.mkdir(parents=True)
    for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE'):
        shutil.copyfile(ROOT / name, source / name)
    shutil.copytree(ROOT / 'src', source / 'src')
    shutil.copytree(ROOT / 'native', source / 'native', ignore=shutil.ignore_patterns('test*.py', '__pycache__'))
    for document in ('LICENSE', 'NOTICE', 'SECURITY.md', 'CONTRIBUTING.md'):
        shutil.copyfile(ROOT / document, destination / document)
    for document in ('README.md', 'README-zh.md'):
        shutil.copyfile(ROOT / document, destination / document)
    shutil.copytree(ROOT / 'docs', destination / 'docs')
    (destination / 'tools').mkdir()
    shutil.copyfile(ROOT / 'tools/identity.py', destination / 'tools/identity.py')
    (destination / 'examples').mkdir()
    for example in sorted((ROOT / 'examples').glob('*.py')):
        shutil.copyfile(example, destination / 'examples' / example.name)
    (destination / 'RUNTIME.txt').write_text(
        'HelloCar Linux receiver. Baseline: Debian 12 (glibc 2.36) or compatible newer Linux.\n'
        'ARM package requires ARMv7 hard-float. Install BlueZ, NetworkManager, libdbus-1-3, iproute2, iw, and FFmpeg.\n'
        'Start with bin/hellocar --help. The launcher selects the bundled native authentication library.\n'
        'Use your own Wi-Fi/Bluetooth driver and a private persisted HiCar identity and key store.\n'
        'This package is a receiver; it contains no OS image, CarLife output, private identity or pairing database.\n', encoding='utf-8')
    rust = rust_sources(destination)
    native = native_sources(destination, options.sources.resolve())
    manifest = dict(schema=1, architecture=arch, project_commit=command('git', '-C', str(ROOT), 'rev-parse', 'HEAD'),
                    rust_toolchain='1.90.0', rust_dependencies=rust, native_sources=native,
                    bundled_runtime=dependencies, minimum_glibc='2.36')
    write_json(destination / 'BUILD.json', manifest)
    evidence = destination / 'share/validation'
    evidence.mkdir(parents=True)
    for relative in ('libexec/hellocar', 'lib/libhellocar_hichain.so'):
        path = destination / relative
        elf(path, arch)
        stem = 'hellocar' if 'libexec' in relative else 'native'
        (evidence / (stem + '-elf.txt')).write_text(command('readelf', '-h', '-A', '-d', str(path)) + '\n')
    exported = command('readelf', '--wide', '--dyn-syms', str(destination / 'lib/libhellocar_hichain.so'))
    for symbol in ('get_instance', 'destroy', 'receive_data', 'start_pake', 'authenticate_peer', 'ED25519_sign'):
        if symbol not in exported:
            raise ValueError('Required native ABI symbol missing: ' + symbol)
    entries = []
    for path in sorted(destination.rglob('*')):
        if path.is_file():
            entries.append(digest(path) + '  ' + path.relative_to(destination).as_posix())
    (destination / 'SHA256SUMS').write_text('\n'.join(entries) + '\n')
    verify(destination)
    archive = destination.with_suffix('.tar.gz')
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
    with archive.open('wb') as output, gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as tar:
            for path in sorted(destination.rglob('*')):
                entry = tar.gettarinfo(str(path), arcname=destination.name + '/' + path.relative_to(destination).as_posix())
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = 'root'
                entry.mtime = epoch
                if path.is_file():
                    with path.open('rb') as stream:
                        tar.addfile(entry, stream)
                else:
                    tar.addfile(entry)
    # Validate the actual delivered archive, not just its staging directory.
    archived = set()
    with tarfile.open(archive, 'r:gz') as tar:
        prefix = destination.name + '/'
        for entry in tar:
            if not entry.name.startswith(prefix) or '..' in Path(entry.name).parts:
                raise ValueError('Unsafe release archive entry')
            if entry.isdir():
                continue
            if not entry.isfile():
                raise ValueError('Unexpected link or special file in release archive')
            relative = entry.name[len(prefix):]
            if relative in archived:
                raise ValueError('Duplicate release archive entry')
            archived.add(relative)
            stream = tar.extractfile(entry)
            if stream is None or hashlib.sha256(stream.read()).hexdigest() != digest(destination / relative):
                raise ValueError('Release archive content mismatch')
    files = {path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
    if archived != files:
        raise ValueError('Release archive is incomplete')
    print(json.dumps(dict(artifact=archive.name, sha256=digest(archive))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--arch', choices=ARCHES)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--native', type=Path)
    parser.add_argument('--sources', type=Path)
    arguments = parser.parse_args()
    if arguments.verify:
        verify(arguments.verify)
    else:
        if not all((arguments.arch, arguments.binary, arguments.native, arguments.sources)):
            parser.error('Building a package requires --arch, --binary, --native and --sources')
        package(arguments)
