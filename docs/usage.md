# Runtime usage

## Services and networking

BlueZ supplies Bluetooth discovery, LE advertising and RFCOMM profiles. NetworkManager supplies a temporary 5 GHz access point and address assignment. OpenSSL 3 supports media cryptography. FFmpeg decodes AAC to 44.1 kHz, stereo, signed 16-bit little-endian PCM, and encodes consumer-supplied 16 kHz mono microphone PCM to AAC for the uplink.

The current radio profile advertises **HelloCar**, uses channel **149 / 5745 MHz**, and assigns the hotspot subnet **192.168.49.0/24**. These settings are currently defined in `src/hicar/radio.rs`, rather than exposed as general channel/subnet options. The selected interface needs AP support and an available regulatory channel. Keep a separate management connection.

The package includes the native authentication library and selected runtime dependencies. Install BlueZ, NetworkManager, libdbus, iproute2, iw, FFmpeg and Python separately. Binaries use a Debian 12 / glibc 2.36 baseline; the ARM package requires ARMv7 hard-float.

The examples use root for system D-Bus and network management. An unprivileged deployment needs appropriate service/device permissions. Run the receiver and consumer under the same UID, with the socket inside a `0700` directory.

## Identity and fixed PIN

```sh
sudo install -d -m 700 /var/lib/hellocar /run/hellocar
sudo python3 tools/identity.py init
sudo python3 tools/identity.py show-pin
```

The default identity is `/var/lib/hellocar/identity.json`; the authentication store is `/var/lib/hellocar/keys`. `init` preserves an existing identity and PIN. Runtime startup reads this file rather than generating a new PIN for each discovery window.

To change the PIN explicitly, `set-pin` reads six ASCII digits from standard input. In Bash:

```sh
read -r -s -p 'New PIN: ' HELLOCAR_NEW_PIN; printf '\n'
printf '%s\n' "$HELLOCAR_NEW_PIN" | sudo python3 tools/identity.py set-pin
unset HELLOCAR_NEW_PIN
```

Re-pair the phone after changing the PIN. Preserve the identity and key store together during upgrades, and give independently running receivers distinct identities. A downstream pairing UI can display the stored PIN during an explicit add-device action.

## Receiver options

| Option | Purpose |
| --- | --- |
| `--network-interface wlan0` | Required: Wi-Fi interface to manage |
| `--pair 120` | Open an explicit pairing window, 5–120 seconds |
| `--peer AA:BB:CC:DD:EE:FF` | Select a previously paired phone |
| `--exclude-peer ADDRESS` | Exclude a Bluetooth address; repeatable |
| `--identity PATH` | Identity file; default `/var/lib/hellocar/identity.json` |
| `--auth-store PATH` | Authentication store; default `/var/lib/hellocar/keys` |
| `--auth-library PATH` | Native library; also `HELLOCAR_AUTH_LIBRARY` |
| `--audio-binary PATH` | AAC decoder; default `/usr/bin/ffmpeg`, also `HELLOCAR_AUDIO_BINARY` |
| `--live-socket PATH` | Consumer socket; default `/run/hellocar/media.sock` |
| `--adapter PATH` | BlueZ adapter; default `/org/bluez/hci0` |
| `--duration 300` | Run for this many seconds; 0 runs until stopped |

Provide `--pair` or `--peer`. One receiver process owns one active phone session. Application-level device selection and arbitration belong to the integrating application.

The packaged `bin/hellocar` launcher selects the adjacent native library and runtime dependencies. Preserve its `bin/`, `libexec/` and `lib/` layout. When running a bare executable, set `--auth-library` or `HELLOCAR_AUTH_LIBRARY` appropriately.

`codec` and the worker commands are development/internal interfaces. Start normal sessions with `run`. Stop with Ctrl+C or SIGTERM; the receiver closes workers, unregisters its Bluetooth services and restores managed network state.

## Troubleshooting

1. Check the phone's Bluetooth, Wi-Fi and HiCar availability, and open an explicit pairing window for a new phone.
2. Check BlueZ and NetworkManager, the chosen interface name, AP support and channel availability.
3. Check the identity file's `0600` mode, writable private key store, native-library path and architecture.
4. If connected without media, start the consumer first and check its socket path and UID. Video decoding must begin at a usable keyframe.
5. For missing PCM, check FFmpeg's AAC decoder and that the phone has started audio playback.

For a report, include the receiver revision, Linux/service versions, phone OS, failure stage and a sanitized timeline. Preserve the failed state before trying identity or pairing resets.
