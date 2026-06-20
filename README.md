# FPC MOH `10a5:9800` — protocol notes and capture demo

Reverse-engineered notes and a minimal working demo for the **Fingerprint
Cards MOH** USB fingerprint sensor (USB ID `10a5:9800`). The demo opens the
device, brings up the TLS-PSK tunnel the sensor expects, and writes raw
fingerprint images to disk in a loop.

This is **not** a driver. It is a small, readable reference for the open
acquisition path — enough to grab images, not enough to enroll, verify, or
match. The closed-source BEP/TEE matching layer is intentionally out of
scope.

## Contents

| File | What it is |
|------|-------------|
| [`fpcmoh-protocol.md`](fpcmoh-protocol.md)     | Protocol notes: USB framing, command table, capture sequence, TLS-PSK details, sealed-blob format. |
| [`fpcmoh-capture-loop.py`](fpcmoh-capture-loop.py) | Self-contained capture demo, ~460 lines of Python. |

## Tested hardware

Everything in this repo was verified against a single unit reporting:

- USB ID: `10a5:9800`
- Sensor: `0x03fe`
- HW ID:  `0x0121`
- Image:  `112x88`, 8-bit grayscale
- Firmware: `26.26.23.31`

Other MOH revisions are likely close but untested. Field widths and offsets
in the protocol notes come from this unit only.

## Requirements

- Linux with libusb. The demo uses `pyusb`, which needs read/write access to
  the device (a udev rule or running as root).
- **Python 3.13+** — needed for `ssl.SSLContext.set_psk_server_callback`.
- OpenSSL built with PSK-AES128-CBC-SHA256 still available at
  `@SECLEVEL=0` (default on most distros).
- Python packages:
  - `pyusb`
  - `cryptography`
  - `Pillow` (only if you want PNG output)

Example udev rule (drop into `/etc/udev/rules.d/70-fpcmoh.rules`, then
`sudo udevadm control --reload && sudo udevadm trigger`):

```udev
SUBSYSTEM=="usb", ATTRS{idVendor}=="10a5", ATTRS{idProduct}=="9800", TAG+="uaccess"
```

Make sure no other driver (`libfprint`/`fprintd`) is currently holding the
device.

## Usage

```sh
pip install pyusb cryptography Pillow
# Or on Arch Linux:
# sudo pacman -S python-pyusb python-cryptography python-pillow
python3 fpcmoh-capture-loop.py --out captures --format png
```

Options:

```
--out PATH         output directory (default: fpcmoh-captures)
--format {pgm,png,raw}   image format (default: pgm)
-n, --count N      stop after N captures (default: loop until Ctrl+C)
-t, --trace        print USB / TLS protocol trace to stderr
```

`pgm` is the most convenient default: no extra dependency, every image
viewer opens it. `raw` is just the `112*88 = 9856` grayscale bytes with no
header.

Touch the sensor when prompted. Press `Ctrl+C` to stop; the demo will issue
the `ABORT` + `SX sleep` cleanup so the next run starts cleanly.

## What's documented

The protocol notes cover what `fpcmoh-capture-loop.py` actually exercises:

- The 12-byte big-endian bulk event header and the events used by the demo
  (`INIT_RESULT`, `ACK`, `TLS_RECORD`, `FINGER_DOWN`, `IMG`).
- The vendor control-transfer command table (`INIT`, `ARM`, `ABORT`,
  `TLS_INIT`, `TLS_DATA`, `INDICATE_S_STATE`, `GET_IMG`, `GET_DEAD_PIXEL`,
  `GET_TLS_KEY`).
- The full open + TLS handshake + capture + close sequence, including why
  `ABORT` is issued between captures.
- TLS-PSK parameters: TLS 1.2, `PSK-AES128-CBC-SHA256`, identity
  `"Disum PSK"`, device-is-client, ≤ 64-byte host→device fragments.
- Layout of the 121-byte sealed PSK blob returned by `GET_TLS_KEY`, and the
  fully deterministic HMAC-SHA256 / AES-256-CBC unwrap.
- Layout of the TLS-plaintext image event after `GET_IMG`.

## Out of scope

- Enroll / verify / identify. Those run in the closed BEP/TEE layer over an
  in-process command bus, not over USB.
- BEP / CAC image metadata semantics, `fpc_tee_*` module ids, the encrypted
  database streaming protocol.
- KPI command `0x0c` and the MOC-style `0x60..0x70` range — present as
  inherited constants but not used on this MOH USB path.

## Acknowledgments

- **GPT 5.5** — used for the bulk of the protocol analysis: cross-referencing
  USB captures against the closed-source binaries, identifying the sealed
  PSK construction, and reconstructing the capture state machine.
- libfprint MR **!396** — *"Add support for FPC MOH device family
  (10a5:9800)"* by the libfprint community. The starting point for this
  reverse-engineering work:
  <https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/396>

## Disclaimer

Independent interpoperability work. No vendor code or vendor confidential
information is included. Field names, constants, and offsets were chosen by
the author based on observed behaviour; they are not authoritative and do
not necessarily match Fingerprint Cards' internal naming. Use at your own
risk.
