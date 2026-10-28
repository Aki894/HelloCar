<p align="center"><b>English</b> · <a href="README-zh.md">简体中文</a></p>

# HelloCar

A wireless HiCar receiver for Linux, built for developers who want to add phone projection to their own applications.

HelloCar handles discovery, pairing, authentication and the projection session. It delivers H.264 video and PCM audio over a local Unix socket and sends touch and key input back to the phone. Your application owns the display, audio playback and user interface.

The receiver is implemented in Rust, with a C adapter for HiChain/HUKS authentication. Python provides identity provisioning, examples and protocol regression tests.

## Scope

HelloCar provides the **receiver side of a wireless HiCar connection**. It can run as a separate process behind a player, an embedded interface or another projection application.

```text
HiCar phone  <── Bluetooth / Wi-Fi ──>  HelloCar  <── Unix socket ──>  Your application
                                      receiver                     video · audio · input
```

| HelloCar handles | Your application handles |
| --- | --- |
| Bluetooth discovery, pairing and connection setup | Device-selection and pairing UI |
| Authentication and persistent device identity | Displaying the pairing PIN to the user |
| Temporary Wi-Fi hotspot and session transport | System networking policy and service supervision |
| Video reception and audio decoding | Video rendering, audio playback and latency policy |
| Touch/key forwarding and session events | Input devices, focus, menus and output integration |

This repository focuses on the receiver and its integration interface. A desktop player, browser receiver, head-unit output, OS image and multi-protocol device manager are outside its scope.

## Features and status

- Wireless discovery and pairing with a persistent six-digit PIN.
- Authentication for new and previously paired devices.
- DMSDP session control and HiSight media transport.
- H.264 passthrough; AAC audio decoded to stereo PCM using FFmpeg.
- Touch, drag, release and key input forwarding.
- Microphone uplink and modem audio sessions; the consumer supplies microphone PCM.
- Independent audio-stream decoding and bounded PCM mixing.
- Session state, audio start/stop and video recovery notifications for consumers.
- Linux command-line receiver and a Rust crate containing the protocol modules.

**Compatibility target:** HarmonyOS 4.2. HarmonyOS 5 and 6 support is outside the current scope. The project is experimental; protocol details and Rust APIs may change before a stable release. Microphone and modem audio paths are experimental and require device validation. The integrating application provides capture, playback and call UI.

## Requirements

- Linux with BlueZ, system D-Bus and NetworkManager.
- Bluetooth BR/EDR and BLE advertising support, plus a Wi-Fi interface with 5 GHz AP support.
- FFmpeg with AAC decoding and encoding; Python 3 for provisioning and the recording example.
- Permission to manage the selected Bluetooth adapter and Wi-Fi interface. The examples below use root.

Binary packages target **x86_64** and **ARMv7 hard-float**, with a Debian 12 / glibc 2.36 baseline. Runtime libraries and their notices are listed in the package manifest.

The current radio profile uses channel **149 / 5745 MHz** and subnet **192.168.49.0/24**. Check that the channel is permitted in your region and supported by your adapter. HelloCar temporarily manages the selected Wi-Fi interface; keep a separate management connection while developing.

## Quick start

Use a Linux package produced by the repository's **Linux receiver build and validation** workflow. Extract the package for your architecture and run these commands from its root. The source checkout's `bin/hellocar` launcher expects the packaged `libexec/` and `lib/` layout.

On Debian-based systems:

```sh
sudo apt-get install bluez network-manager libdbus-1-3 iproute2 iw ffmpeg python3
sha256sum -c SHA256SUMS
sudo install -d -m 700 /var/lib/hellocar /run/hellocar
sudo python3 tools/identity.py init
sudo python3 tools/identity.py show-pin
```

`init` creates a private identity and PIN once. Repeating it preserves the existing identity. Keep the identity and authentication store across upgrades.

Start the recording example in one terminal. It acts as the local media consumer:

```sh
sudo python3 examples/record_media.py \
  --output /var/tmp/hellocar-capture --duration 120
```

In another terminal, start the receiver. Replace `wlan0` with the interface to use for the hotspot:

```sh
sudo bin/hellocar run --network-interface wlan0 --pair 120
```

Enable Bluetooth and Wi-Fi on the phone, select **HelloCar** when HiCar discovers it, and enter the PIN shown by `show-pin`. The example saves `video.h264` and `audio.s16le`, with a default limit of 120 seconds or 64 MiB. It records media rather than displaying or playing it.

To connect to a previously paired phone by its Bluetooth address:

```sh
sudo bin/hellocar run --network-interface wlan0 --peer AA:BB:CC:DD:EE:FF
```

See [usage and troubleshooting](docs/usage.md) for identity management, permissions and command-line options.

## Integration

For most applications, run HelloCar as a **separate process** and implement a consumer for the [local media protocol](docs/media-protocol.md):

1. Listen on a private Unix stream socket before starting the receiver.
2. Receive configuration, session events, H.264 access units and PCM audio.
3. Send touch and key feedback over the same socket.
4. Handle disconnects, audio generations and keyframe recovery in your renderer/player.

The default socket is `/run/hellocar/media.sock`; set `--live-socket` to change it. HelloCar connects as the **client**. The [recording example](examples/record_media.py) shows the consumer side and bounded media handling.

The Rust crate exposes `hellocar::hicar` for protocol development and deeper integration. These are implementation-level modules, not a stable high-level player API. The native authentication library and Linux services remain runtime dependencies.

## Layout

| Path | Contents |
| --- | --- |
| [`src/`](src) | Rust library and command-line entry point |
| [`src/hicar/`](src/hicar) | Discovery, authentication, session control, media and input |
| [`native/`](native) | C authentication adapter and pinned upstream source definitions |
| [`examples/`](examples) | Local media recorder and provisioning/example tests |
| [`tests/reference/`](tests/reference) | Synthetic Python protocol reference implementations |
| [`tools/`](tools) | Identity provisioning, regression runners and packaging |
| [`docs/`](docs) | Runtime usage and consumer protocol |
| [`.github/workflows/`](.github/workflows) | Linux builds, regression tests and package validation |

## Development

Rust is pinned in `rust-toolchain.toml`; Rust dependencies are locked in `Cargo.lock`, and native sources in `native/sources.json`.

GitHub Actions builds both architectures, runs the host integration suites and ARM QEMU protocol/authentication tests, checks the package layout and ELF ABI, and uploads packages with SHA256 manifests. The build entry point is `tools/build.sh`.

Provisioning and example tests can also run without compiling the receiver:

```sh
python3 -m unittest discover -s examples -p 'test_*.py'
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for changes and tests, and [SECURITY.md](SECURITY.md) for handling identities and reports.

## License

HelloCar's project code is licensed under [MIT](LICENSE). Native dependencies and bundled runtime libraries retain their own licenses; see [NOTICE](NOTICE) and the package's license directory.

HiCar, Huawei and HarmonyOS are trademarks of their respective owners. HelloCar is an independent interoperability project.
