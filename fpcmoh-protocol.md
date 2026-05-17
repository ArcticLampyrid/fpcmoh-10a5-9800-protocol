# FPC MOH USB/TLS protocol notes

Notes for the demo capture path against the FPC MOH (`10a5:9800`) sensor — what
`fpcmoh-capture-loop.py` actually uses. Not a vendor spec. All offsets and
sizes come from one tested unit (`sensor=0x03fe`, `hw_id=0x0121`, image
`112x88`, firmware `26.26.23.31`).

## Transport

- USB VID:PID `10a5:9800`, interface `0`, bulk IN endpoint `0x82`.
- Host → device: vendor control transfers
  - `bmRequestType = 0x40` (OUT) or `0xc0` (IN)
  - `bRequest = command id`
  - `wValue = command-specific selector`
  - `wIndex = 0`
- Device → host async messages and TLS records: bulk IN on `0x82`.

Bulk header fields are **big-endian**. Small control-transfer payloads
(session id, capture id) are **little-endian**.

## Bulk event framing

Every bulk message starts with a 12-byte big-endian header:

| offset | field      | size  |
|--------|------------|-------|
| 0      | event_id   | 4     |
| 4      | total_len  | 4     |
| 8      | status     | 4     |
| 12     | body       | total_len − 12 |

`total_len` is the **full** event length including the header. A single event
may span several bulk reads — keep reading until you have `total_len` bytes.

### Events used by the demo

| id     | name          | notes                                       |
|--------|---------------|---------------------------------------------|
| `0x02` | `INIT_RESULT` | Plain bulk event after `INIT` (38 bytes).   |
| `0x04` | `ACK`         | Plaintext-only, after `GET_DEAD_PIXEL` (12). |
| `0x05` | `TLS_RECORD`  | Encrypted TLS bytes from device.            |
| `0x06` | `FINGER_DOWN` | Plain event, exactly 12 bytes.              |
| `0x08` | `IMG`         | Plaintext image event inside TLS.           |

### `INIT_RESULT` body

```c
struct fpc_init_result {
    be32 event_id;        // 0x02
    be32 total_len;       // 38
    be32 status;          // 0 on success
    be16 sensor;          // observed 0x03fe
    be16 hw_id;           // observed 0x0121
    be16 image_width;     // observed 112
    be16 image_height;    // observed 88
    char fw_version[16];  // observed "26.26.23.31"
    be16 fw_caps;         // observed 0x0002
};
```

## Command table

| cmd    | name                  | dir | value         | payload                  |
|--------|-----------------------|-----|---------------|--------------------------|
| `0x01` | `INIT`                | OUT | `0x01`        | 4-byte LE session id     |
| `0x02` | `ARM`                 | OUT | `0x01`        | 4-byte LE capture id     |
| `0x03` | `ABORT`               | OUT | `0x01`        | none                     |
| `0x05` | `TLS_INIT`            | OUT | `0x01`        | none                     |
| `0x06` | `TLS_DATA`            | OUT | `0x01`        | TLS bytes, ≤ 64 per call |
| `0x08` | `INDICATE_S_STATE`    | OUT | `0x10`/`0x11` | none (S0 wake / SX sleep)|
| `0x09` | `GET_IMG`             | OUT | `0x00`        | none                     |
| `0x0a` | `GET_DEAD_PIXEL`      | OUT | `0x00`        | none                     |
| `0x0b` | `GET_TLS_KEY`         | IN  | `0x00`        | 121-byte sealed PSK blob |

## Capture sequence

```text
# Open + key
OUT 0x01 v=0x01  payload=session_id_le32
BULK IN          event 0x02 INIT_RESULT
OUT 0x08 v=0x10                            # S0 wake
IN  0x0b v=0x00  len=121                   # sealed PSK blob

# TLS up (device is the TLS client)
OUT 0x03 v=0x01                            # clear stale capture state
OUT 0x05 v=0x01                            # start handshake
BULK IN          event 0x05 (TLS bytes from device)
OUT 0x06 v=0x01  payload=TLS bytes         # ≤64 bytes per call
                                           # ... repeat until handshake done

# Per image (loop)
OUT 0x02 v=0x01  payload=capture_id_le32   # 0x0701100f works
BULK IN          event 0x06 FINGER_DOWN
OUT 0x09 v=0x00
BULK IN          event 0x05 (TLS records)
                 → TLS plaintext event 0x08 (image)
OUT 0x0a v=0x00
BULK IN          event 0x05 (TLS records)
                 → TLS plaintext event 0x04 (ACK)
OUT 0x03 v=0x01                            # deactivate this capture

# Close
... optional TLS close_notify via OUT 0x06 ...
OUT 0x03 v=0x01
OUT 0x08 v=0x11                            # SX sleep
```

Why the `ABORT` between captures: it matches the closed-source path and
prevents the sensor from sticking in capture mode if the demo is killed.

If the previous run died after `ARM`, a stale `FINGER_DOWN` (`0x06`) can sit
in the bulk FIFO and confuse the next TLS handshake. The demo issues `ABORT`
and drains the FIFO before `TLS_INIT` to clear it.

## TLS

- TLS 1.2, **device is the client, host is the server**.
- Negotiated suite: `TLS-PSK-WITH-AES-128-CBC-SHA256`.
- PSK identity (from device): `"Disum PSK"`.
- On modern OpenSSL the cipher string must include `@SECLEVEL=0` to allow
  plain PSK.
- Host → device TLS bytes must be fragmented to **≤ 64 bytes per
  `TLS_DATA`** control transfer.
- Device → host TLS bytes arrive as bulk event `0x05`; feed the body
  (everything after the 12-byte event header) straight into the TLS engine.

Inside the TLS plaintext stream the same 12-byte big-endian event header is
reused. After `GET_IMG`, expect event `0x08` (image). After `GET_DEAD_PIXEL`,
expect event `0x04` (ACK).

## Sealed PSK blob (response to `GET_TLS_KEY`)

121 bytes, little-endian header:

```c
struct fpc_sealed_blob {
    le32 magic;       // 0x0dec0ded
    le32 ct_off;      // 28
    le32 ct_len;      // 32
    le32 aad_off;     // 76
    le32 aad_len;     // 13
    le32 tag_off;     // 89
    le32 tag_len;     // 32
    u8   data[];
};
```

Unwrap:

```text
aad      = "FPC TLS Keys\0"                             # 13 bytes
hmac_key = SHA256("FPC_HMAC_KEY\0")
seal_key = SHA256("FPC_SEALING_KEY\0")

tag      = HMAC-SHA256(hmac_key, aad || ciphertext)     # verify against blob
psk      = AES-256-CBC-Decrypt(seal_key, iv=0, ciphertext)[:32]
```

Both keys are derived from constant labels — the "sealing" looks like
SGX-style code but the Linux build is fully deterministic.

## TLS plaintext image event

After `GET_IMG`, the TLS plaintext stream yields:

```c
struct fpc_tls_plain_image {
    be32 event_id;    // 0x08
    be32 total_len;   // observed 9890
    be32 status;      // 0
    u8   meta[22];    // capture metadata, consumed by the closed BEP layer
    u8   pixels[image_width * image_height];  // grayscale, e.g. 112*88 = 9856
};
```

Pixel window: `event[34 .. 34 + width*height)`.

The 22 metadata bytes vary per capture and feed BEP/CAC quality logic. They
are not needed to render the raw fingerprint, so the demo skips them.

## Out of scope for this demo

These would only matter for a full driver, not for raw capture:

- Enroll / verify / identify flow. Those run in the closed-source BEP/TEE
  layer over an in-process command bus, not over USB. The USB capture path
  is identical for all three.
- `fpc_tee_*` module ids, BEP image metadata key meanings, encrypted DB blob
  streaming.
- KPI command `0x0c` (defined but not seen in this MOH port).
- The MOC-style `0x60..0x70` command range (inherited constants only, not
  used by the MOH USB path).
