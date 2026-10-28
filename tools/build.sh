#!/bin/bash
# Build on GitHub Actions only; local work edits source and runs Python checks.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true || { echo 'Use the Linux receiver GitHub Actions workflow to compile.' >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
git config --global --add safe.directory "$root"
export RUST_VERSION=1.90.0
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
python3 -m venv .build/test-python
python=.build/test-python/bin/python
"$python" -m pip install --disable-pip-version-check --require-hashes -r tests/requirements.txt
"$python" -m compileall -q tools native tests
"$python" -m unittest discover -s examples -p 'test_*.py'
python3 native/fetch.py "$root/.build/native-sources"
cmake -S native -B .build/native-host -G Ninja \
  -DSOURCE_ROOT="$root/.build/native-sources" -DCMAKE_BUILD_TYPE=Release
cmake --build .build/native-host --parallel 4
"$python" native/test_library.py .build/native-host/libhellocar_hichain.so
"$python" native/test_pake.py .build/native-host/libhellocar_hichain.so
cargo +"$RUST_VERSION" test --locked
cargo +"$RUST_VERSION" build --locked
host=target/debug/hellocar
for suite in test-hicar-rust test-hicar-rust-hisight test-hicar-rust-dmsdp \
             test-hicar-rust-live test-hicar-rust-radio test-hicar-rust-backend; do
  "$python" "tools/$suite.py" "$host"
done
"$python" tools/test-hicar-rust-auth.py "$host" .build/native-host/libhellocar_hichain.so
"$python" tools/test-hicar-rust-session.py "$host" .build/native-host/libhellocar_hichain.so
cargo +"$RUST_VERSION" build --release --locked
cmake -S native -B .build/native-armv7 -G Ninja \
  -DSOURCE_ROOT="$root/.build/native-sources" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE="$root/native/armhf.cmake"
cmake --build .build/native-armv7 --parallel 4
cargo +"$RUST_VERSION" build --release --locked --target armv7-unknown-linux-gnueabihf
python3 tools/package.py --arch x86_64 --binary target/release/hellocar \
  --native .build/native-host/libhellocar_hichain.so --sources .build/native-sources
python3 tools/package.py --arch armv7 --binary target/armv7-unknown-linux-gnueabihf/release/hellocar \
  --native .build/native-armv7/libhellocar_hichain.so --sources .build/native-sources
export HELLOCAR_RUST_RUNNER=$(python3 -c 'import json,os; print(json.dumps(["qemu-arm","-L","/usr/arm-linux-gnueabihf","-E","LD_LIBRARY_PATH="+os.getcwd()+"/dist/hellocar-linux-armv7/lib:/usr/arm-linux-gnueabihf/lib"]))')
arm=target/armv7-unknown-linux-gnueabihf/release/hellocar
for suite in test-hicar-rust test-hicar-rust-hisight test-hicar-rust-dmsdp; do
  "$python" "tools/$suite.py" "$arm"
done
"$python" tools/test-hicar-rust-radio.py "$arm" --contracts-only
"$python" tools/test-hicar-rust-auth.py "$arm" .build/native-host/libhellocar_hichain.so \
  "$root/.build/native-armv7/libhellocar_hichain.so"
"$python" tools/test-hicar-rust-session.py "$arm" .build/native-host/libhellocar_hichain.so \
  "$root/.build/native-armv7/libhellocar_hichain.so"
unset HELLOCAR_RUST_RUNNER
dist/hellocar-linux-x86_64/bin/hellocar --help
printf '%s\n' '{"op":"uint","value":128}' | dist/hellocar-linux-x86_64/bin/hellocar codec | python3 -c 'import json,sys; assert json.load(sys.stdin)["ok"]'
qemu-arm -L /usr/arm-linux-gnueabihf -E LD_LIBRARY_PATH="$root/dist/hellocar-linux-armv7/lib:/usr/arm-linux-gnueabihf/lib" \
  dist/hellocar-linux-armv7/libexec/hellocar --help
python3 tools/package.py --verify dist/hellocar-linux-x86_64
python3 tools/package.py --verify dist/hellocar-linux-armv7
python3 -c 'import json,os,pathlib; pathlib.Path("dist/validation.json").write_text(json.dumps(dict(commit=os.environ["GITHUB_SHA"],host_full_tests=True,armv7_qemu_protocol_crypto_auth_session=True,package_checksums=True,native_abi=True),indent=2)+"\n")'
(cd dist && sha256sum -- *.tar.gz validation.json > SHA256SUMS && sha256sum -c SHA256SUMS)
