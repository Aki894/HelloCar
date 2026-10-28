# Contributing

HelloCar focuses on the Linux wireless HiCar receiver and its integration interface. Contributions to protocol compatibility, connection recovery, media handling, input, documentation and synthetic tests are welcome.

## Structure and interfaces

Keep protocol and session logic in `src/hicar/`, native authentication adaptation in `native/`, and consumer examples in `examples/`. Application-specific rendering, playback and device menus belong in downstream consumers. See the [media protocol](docs/media-protocol.md) before changing the consumer interface.

Prefer a reproducible transcript or synthetic test for protocol changes. Cover fragmented/coalesced messages, malformed input, EOF, timeouts, duplicate messages, stale sessions, backpressure and cleanup where relevant. Test identities and media must be generated fixtures.

## Validation

Edit source locally; Linux and native compilation runs in GitHub Actions. The workflow installs the pinned Rust toolchain and native dependencies and invokes `tools/build.sh`. It runs host unit/integration tests, ARM QEMU checks and package validation before uploading artifacts.

Local Python checks:

```sh
python3 -m unittest discover -s examples -p 'test_*.py'
python3 -m compileall -q tools native tests examples
```

Record the checks you actually ran. For hardware-dependent changes, include the Linux/services versions, phone OS, relevant radio capabilities and observed connection stage. Keep CI, emulation and hardware results separate.

## Pull requests

Describe the problem, the resulting behavior and validation. Include corresponding documentation or protocol updates when an interface changes. Dependency updates should retain pinned revisions and license notices.

Keep private identities, PINs, pairing stores, vendor binaries and raw captures out of commits, logs and test fixtures. See [SECURITY.md](SECURITY.md).
