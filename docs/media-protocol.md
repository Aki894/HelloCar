# Local media protocol

`hellocar run` connects as a Unix stream socket **client** to `--live-socket`. The integrating application listens as the server before starting the receiver. Both processes should use the same UID and a private socket directory.

The interface carries received video, decoded audio, session events and input feedback. See [`examples/record_media.py`](../examples/record_media.py) for a bounded consumer. This is a pre-stable interface; pin a receiver revision when integrating it.

## Record layout

Each record starts with a four-byte little-endian length `N`, followed by a 12-byte header and `N-12` bytes of payload. `N` excludes the length field itself.

| Field | Bytes | Meaning |
| --- | --- | --- |
| `N` | 4 | u32 little-endian: 12 + payload size |
| `kind` | 1 | Record type |
| `flags` | 1 | Type-specific flags |
| reserved | 2 | Zero |
| `pts_us` | 8 | u64 little-endian: local timestamp in microseconds |
| payload | Variable | Type-specific data |

A stream read can contain a partial record or multiple records. Bound record sizes and queue depth. The current video payload limit is 512 KiB; consumers should also bound stored media size and duration.

## Receiver to consumer

| Kind | Flags / payload | Meaning |
| --- | --- | --- |
| 1 | Three little-endian u32 values: width, height, fps | Configuration; currently 800 × 480 / 30 fps |
| 2 | H.264 Annex B; flags bit 0 marks a usable IDR | Start decoding at a complete keyframe; preserve access-unit order |
| 3 | Signed 16-bit LE PCM, 44100 Hz, stereo interleaved; flags 0 media, 3 modem/call | Normally 882 samples per channel / 20 ms / 3528 bytes |
| 4 | Empty payload; flags bit 0 indicates active source | Stop stale playback and release input on disconnect; await a keyframe for a new session |
| 5 | One-byte payload: 0 stops audio, 1 starts audio; flags select the audio role | Clear the previous audio generation's buffers for that role |
| 6 | Empty payload | Video recovery fence: discard pending frames and await a new keyframe |
| 7 | UTF-8 JSON: `generation`, `active`, `sample_rate=16000`, `channels=1` | Start/stop the consumer's microphone capture for this generation |

PTS values describe local order and pacing. The current video path uses a local timestamp; audio pacing follows the local sample count. Consumers supply bounded buffering and their own playback clock.

The receiver retries consumer connections. On connection it reports state/configuration and waits for a usable keyframe. Consumers must handle EOF, reconnects and source generations. Backpressure triggers video recovery; avoid an unbounded playback queue.

## Consumer to receiver

Send `kind=129` records over the same socket, with flags/reserved/PTS set to zero and a UTF-8 JSON payload. The total `N` must be between 12 and 4096.

```python
def feedback(sock, value):
    import json, struct
    payload = json.dumps(value, separators=(',', ':')).encode('utf-8')
    if len(payload) > 4084:
        raise ValueError('feedback too large')
    sock.sendall(struct.pack('<IBBHQ', 12 + len(payload), 129, 0, 0, 0) + payload)
```

Supported messages:

```json
{"type":"touch","contacts":[{"x":0.5,"y":0.5,"down":true}]}
{"type":"touch","contacts":[]}
{"type":"key-press","code":1}
{"type":"keyframe"}
```

Touch coordinates are normalized to `[0,1]`. Send the first contact to press or move, and an empty contact list to release. The current bridge uses only the first contact. `key-press` generates paired press/release events: 0 home, 1 back, 2 confirm, 3 left, 4 right, 5 up, 6 down, 7 play/pause, 8 next, 9 previous. `keyframe` enters video recovery and waits for the source's next usable keyframe.

Send an empty contact list and clear locally held keys when losing the input device, changing source or stopping the consumer. Identity, PIN and authentication keys are outside this media interface.

## Microphone uplink

For a kind 7 request with `active=true`, acquire **16000 Hz, mono, signed 16-bit little-endian PCM**. Return kind **130** records over the same socket: flags/reserved are zero, `pts_us` is the capture timestamp, and the payload is an eight-byte little-endian generation followed by PCM bytes. Use even PCM lengths of at most 16384 bytes; 20 ms / 640-byte blocks are suitable.

The generation comes from the current request. Stop capture on `active=false`, source disconnect, EOF or replacement by a new generation. Discard queued old PCM. The receiver fences generations, AAC-encodes the accepted PCM and transmits encrypted RTP to the negotiated phone endpoint.

[`examples/microphone_pcm.py`](../examples/microphone_pcm.py) provides the record encoder. The recording example accepts microphone requests but does not capture or supply microphone audio. The integrating application selects the physical input and manages capture permissions and echo control.


Microphone AAC RTP uses the synchronized peer clock (local monotonic time plus the measured offset), at 90 kHz. Service changes retire the prior RTP reorder/decoder epoch. Pending audio is bounded across the decoder pipe and PCM queue; call and normal speaker endpoints are isolated. Trusted automatic reconnection uses outgoing Nearby CCMP and business-channel negotiation.

The microphone RTP SSRC selects virtual input stream **1100**. It is independent of the DMSDP `DataSessionID`, which identifies the control session. Substituting the control identifier can let packets reach the phone while leaving its virtual microphone decoder without readable PCM.
