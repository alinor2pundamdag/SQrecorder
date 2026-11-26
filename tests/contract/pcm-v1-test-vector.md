# PCM block v1 byte fixture

A minimal valid example for a mono S16LE block:

- Sample rate: 48,000 Hz
- Channels: 1
- Format: S16LE (1)
- Frames: 2
- First frame: 0
- Monotonic timestamp: 1,000,000 ns
- Capture epoch: 1
- Payload length: 4 bytes
- Sequence: 0
- Flags: 0
- Samples: `0x0001`, `0xFFFE`

Expected 64-byte header, grouped by field (hex bytes):

```text
53 51 50 43  01 00  40 00
00 00 00 00  80 BB 00 00
01 00  01 00  02 00 00 00
00 00 00 00 00 00 00 00
40 42 0F 00 00 00 00 00
01 00 00 00 00 00 00 00
04 00 00 00 00 00 00 00
00 00 00 00  00 00 00 00
```

Append payload bytes `01 00 FE FF`. Total block size is 68 bytes. This fixture is a serialization reference; decoder implementation and automated round-trip tests are added with the PCM implementation.
