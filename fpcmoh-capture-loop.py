#!/usr/bin/env python3
"""Capture raw fingerprint images from an FPC MOH (10a5:9800) sensor.

Demo of the open USB + TLS-PSK acquisition path. Press Ctrl+C to stop.

Requires Python 3.13+ (for ssl.SSLContext.set_psk_server_callback).
Runtime deps: pyusb, cryptography, Pillow (only for PNG output).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import signal
import ssl
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

import usb.core
import usb.util
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from PIL import Image
except ImportError:
    Image = None


# --- USB ---------------------------------------------------------------------
VID, PID = 0x10A5, 0x9800
IFACE = 0
EP_IN = 0x82
EP_IN_MAX = 2048
CTRL_TIMEOUT_MS = 5000
BULK_TIMEOUT_MS = 30000
TLS_FRAGMENT_MAX = 64  # host -> device TLS bytes per control OUT 0x06

# Vendor commands (control OUT unless noted).
CMD_INIT = 0x01        # v=0x01, payload=session_id_le32
CMD_ARM = 0x02         # v=0x01, payload=capture_id_le32
CMD_ABORT = 0x03       # v=0x01
CMD_TLS_INIT = 0x05         # v=0x01
CMD_TLS_DATA = 0x06         # v=0x01, payload=TLS bytes (<=64)
CMD_INDICATE_S_STATE = 0x08 # v=0x10 (S0 wake) or v=0x11 (SX sleep)
CMD_GET_IMG = 0x09          # v=0x00
CMD_GET_DEAD_PIXEL = 0x0A   # v=0x00
CMD_GET_TLS_KEY = 0x0B      # control IN, returns 121-byte sealed PSK blob

# Bulk event ids (12-byte big-endian header: event_id, total_len, status).
EVT_INIT_RESULT = 0x02
EVT_ACK = 0x04
EVT_TLS_RECORD = 0x05
EVT_FINGER_DOWN = 0x06
EVT_IMG = 0x08

DEFAULT_CAPTURE_ID = 0x0701100F

# --- Sealed PSK blob ---------------------------------------------------------
SEAL_MAGIC = 0x0DEC0DED
SEAL_AAD = b"FPC TLS Keys\0"
SEAL_KEY = hashlib.sha256(b"FPC_SEALING_KEY\0").digest()
SEAL_HMAC = hashlib.sha256(b"FPC_HMAC_KEY\0").digest()
TLS_KEY_SIZE = 32
TLS_PSK_IDENTITY = "Disum PSK"


stop = False
trace = False


def handle_sigint(*_):
    global stop
    if not stop:
        print("\nstopping...", flush=True)
    stop = True


def _hex_preview(data: bytes, limit: int = 32) -> str:
    if not data:
        return ""
    head = data[:limit].hex()
    return head + ("..." if len(data) > limit else "")


def trace_ctrl(direction: str, request: int, value: int, data: bytes):
    if not trace:
        return
    preview = _hex_preview(data)
    sep = "  " if preview else ""
    print(f"ctrl {direction:<3} 0x{request:02x} v=0x{value:02x} len={len(data)}{sep}{preview}",
          file=sys.stderr, flush=True)


def trace_bulk(tag: str, data: bytes):
    if not trace:
        return
    preview = _hex_preview(data)
    sep = "  " if preview else ""
    print(f"bulk {tag:<5} len={len(data)}{sep}{preview}",
          file=sys.stderr, flush=True)


# Map known event IDs to human-readable names.
_EVT_NAMES = {
    EVT_INIT_RESULT: "INIT_RESULT",
    EVT_ACK:         "ACK",
    EVT_TLS_RECORD:  "TLS_RECORD",
    EVT_FINGER_DOWN: "FINGER_DOWN",
    EVT_IMG:         "IMG",
}


def trace_event(tag: str, evt: "Event"):
    """Trace a parsed event (USB-level or TLS plaintext)."""
    if not trace:
        return
    name = _EVT_NAMES.get(evt.event_id, f"0x{evt.event_id:08x}")
    payload = evt.data[12:]  # skip the 12-byte header
    preview = _hex_preview(payload)
    sep = "  " if preview else ""
    print(f"evt  {tag:<5} {name} status={evt.status} "
          f"total={evt.total_len} payload={len(payload)}{sep}{preview}",
          file=sys.stderr, flush=True)


def trace_msg(msg: str):
    """Trace a one-line informational note (handshake progress, etc.)."""
    if not trace:
        return
    print(f"info {msg}", file=sys.stderr, flush=True)


@dataclass
class InitInfo:
    width: int
    height: int


@dataclass
class Event:
    event_id: int
    total_len: int
    status: int
    data: bytes


# --- USB helpers -------------------------------------------------------------

def open_device():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise SystemExit(f"device {VID:04x}:{PID:04x} not found")
    for op in (
        lambda: dev.set_auto_detach_kernel_driver(True),
        lambda: dev.reset(),
        lambda: dev.set_configuration(),
    ):
        try:
            op()
        except (AttributeError, NotImplementedError, usb.core.USBError):
            pass
    usb.util.claim_interface(dev, IFACE)
    return dev


def ctrl_out(dev, request, value, payload=b""):
    trace_ctrl("OUT", request, value, payload)
    sent = dev.ctrl_transfer(0x40, request, value, 0, payload, timeout=CTRL_TIMEOUT_MS)
    if sent != len(payload):
        raise IOError(f"short ctrl OUT 0x{request:02x}: {sent}/{len(payload)}")


def ctrl_in(dev, request, value, length):
    data = bytes(dev.ctrl_transfer(0xC0, request, value, 0, length, timeout=CTRL_TIMEOUT_MS))
    trace_ctrl("IN", request, value, data)
    return data


def bulk_read(dev):
    while True:
        if stop:
            raise KeyboardInterrupt
        try:
            data = bytes(dev.read(EP_IN, EP_IN_MAX, timeout=BULK_TIMEOUT_MS))
        except usb.core.USBTimeoutError:
            continue  # idle while waiting for a finger
        trace_bulk("IN", data)
        return data


def read_event(dev, expected=None) -> Event:
    buf = bytearray(bulk_read(dev))
    if len(buf) < 12:
        raise IOError(f"short bulk event: {len(buf)} bytes")
    event_id, total_len, status = struct.unpack(">III", buf[:12])
    while len(buf) < total_len:
        buf.extend(bulk_read(dev))
    if expected is not None and event_id != expected:
        raise IOError(f"got event 0x{event_id:08x}, expected 0x{expected:08x}")
    evt = Event(event_id, total_len, status, bytes(buf[:total_len]))
    trace_event("USB", evt)
    return evt


def drain_bulk(dev, timeout_ms=100, max_chunks=16):
    """Discard any bulk packets queued by a previous interrupted run."""
    for _ in range(max_chunks):
        try:
            data = bytes(dev.read(EP_IN, EP_IN_MAX, timeout=timeout_ms))
        except (usb.core.USBTimeoutError, usb.core.USBError):
            return
        if not data:
            return
        trace_bulk("DRAIN", data)


def tls_write(dev, data):
    for i in range(0, len(data), TLS_FRAGMENT_MAX):
        ctrl_out(dev, CMD_TLS_DATA, 0x01, data[i:i + TLS_FRAGMENT_MAX])


# --- Sealed PSK --------------------------------------------------------------

def unwrap_psk(blob: bytes) -> bytes:
    """Verify HMAC tag and AES-256-CBC decrypt the sealed PSK blob."""
    magic, ct_off, ct_len, aad_off, aad_len, tag_off, tag_len = struct.unpack_from("<7I", blob)
    if magic != SEAL_MAGIC:
        raise ValueError(f"sealed key bad magic: 0x{magic:08x}")
    aad = blob[aad_off:aad_off + aad_len]
    ciphertext = blob[ct_off:ct_off + ct_len]
    tag = blob[tag_off:tag_off + tag_len]
    if aad != SEAL_AAD:
        raise ValueError(f"sealed key unexpected AAD: {aad!r}")
    expected_tag = hmac.new(SEAL_HMAC, aad + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("sealed key integrity check failed")
    dec = Cipher(algorithms.AES(SEAL_KEY), modes.CBC(b"\0" * 16)).decryptor()
    return (dec.update(ciphertext) + dec.finalize())[:TLS_KEY_SIZE]


# --- TLS over USB ------------------------------------------------------------

class TlsChannel:
    """TLS 1.2 PSK server tunneled over the FPC USB framing.

    The device is the TLS client; we feed ciphertext through MemoryBIOs and
    transmit it via vendor control transfers. No real socket is involved.
    """

    def __init__(self, dev, psk: bytes):
        self.dev = dev
        self.psk = bytes(psk)
        self.in_bio = ssl.MemoryBIO()
        self.out_bio = ssl.MemoryBIO()
        self.plain = bytearray()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # @SECLEVEL=0 is needed for plain PSK on modern OpenSSL.
        ctx.set_ciphers("PSK-AES128-CBC-SHA256:@SECLEVEL=0")
        ctx.set_psk_server_callback(
            lambda identity: self.psk if identity == TLS_PSK_IDENTITY else b""
        )
        self.ssl = ctx.wrap_bio(self.in_bio, self.out_bio, server_side=True)

    def _flush_out(self):
        out = self.out_bio.read()
        if out:
            tls_write(self.dev, out)

    def _feed_in(self):
        evt = read_event(self.dev, EVT_TLS_RECORD)
        self.in_bio.write(evt.data[12:])

    def handshake(self):
        trace_msg("TLS handshake starting")
        while True:
            try:
                self.ssl.do_handshake()
                self._flush_out()
                trace_msg("TLS handshake complete")
                return
            except ssl.SSLWantWriteError:
                self._flush_out()
            except ssl.SSLWantReadError:
                self._flush_out()
                self._feed_in()

    def _read_chunk(self):
        while True:
            try:
                chunk = self.ssl.read(EP_IN_MAX)
                if not chunk:
                    raise IOError("TLS closed")
                return chunk
            except ssl.SSLWantWriteError:
                self._flush_out()
            except ssl.SSLWantReadError:
                self._flush_out()
                self._feed_in()

    def read_plain_event(self) -> Event:
        while len(self.plain) < 12:
            self.plain.extend(self._read_chunk())
        event_id, total_len, status = struct.unpack(">III", self.plain[:12])
        while len(self.plain) < total_len:
            self.plain.extend(self._read_chunk())
        data = bytes(self.plain[:total_len])
        del self.plain[:total_len]
        evt = Event(event_id, total_len, status, data)
        trace_event("TLS", evt)
        return evt

    def close_notify(self):
        try:
            self.ssl.unwrap()
        except (ssl.SSLError, OSError):
            pass
        try:
            self._flush_out()
        except Exception:
            pass


# --- Init parsing / output ---------------------------------------------------

def parse_init(data: bytes) -> InitInfo:
    event_id, _, status = struct.unpack_from(">III", data)
    if event_id != EVT_INIT_RESULT or status != 0:
        raise IOError(f"bad INIT_RESULT event=0x{event_id:08x} status={status}")
    # skip sensor (12), hw_id (14); width @ 16, height @ 18
    width, height = struct.unpack_from(">HH", data, 16)
    return InitInfo(width, height)


def next_path(out_dir: Path, fmt: str) -> Path:
    ext = {"raw": ".raw", "png": ".png", "pgm": ".pgm"}[fmt]
    i = 0
    while True:
        p = out_dir / f"fingerprint-{i:04d}{ext}"
        if not p.exists():
            return p
        i += 1


def save_image(path: Path, fmt: str, pixels: bytes, info: InitInfo):
    if fmt == "raw":
        path.write_bytes(pixels)
    elif fmt == "png":
        if Image is None:
            raise RuntimeError("Pillow is not installed; cannot write PNG")
        Image.frombytes("L", (info.width, info.height), pixels).save(path)
    else:  # pgm
        with path.open("wb") as f:
            f.write(f"P5\n{info.width} {info.height}\n255\n".encode())
            f.write(pixels)


def try_send(dev, request, value, payload=b""):
    """Best-effort vendor OUT; swallows errors used only for cleanup."""
    try:
        ctrl_out(dev, request, value, payload)
    except Exception:
        pass


# --- Main --------------------------------------------------------------------

def main():
    signal.signal(signal.SIGINT, handle_sigint)
    p = argparse.ArgumentParser(description="Capture FPC MOH fingerprint images.")
    p.add_argument("--out", default="fpcmoh-captures", help="output directory")
    p.add_argument("--format", choices=("pgm", "png", "raw"), default="pgm")
    p.add_argument("-n", "--count", type=int, default=0,
                   help="stop after N captures (default: until Ctrl+C)")
    p.add_argument("-t", "--trace", action="store_true",
                   help="print USB/TLS protocol trace to stderr")
    args = p.parse_args()

    global trace
    trace = args.trace

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    dev = open_device()
    tls: TlsChannel | None = None
    try:
        # 1) INIT + sealed PSK
        session_id = int.from_bytes(os.urandom(4), "little")
        ctrl_out(dev, CMD_INIT, 0x01, struct.pack("<I", session_id))
        info = parse_init(read_event(dev, EVT_INIT_RESULT).data)
        print(f"sensor image: {info.width}x{info.height}")
        ctrl_out(dev, CMD_INDICATE_S_STATE, 0x10)  # S0 wake
        psk = unwrap_psk(ctrl_in(dev, CMD_GET_TLS_KEY, 0, 121))

        # 2) Clear any stale capture state, then start TLS
        try_send(dev, CMD_ABORT, 0x01)
        drain_bulk(dev)
        ctrl_out(dev, CMD_TLS_INIT, 0x01)
        tls = TlsChannel(dev, psk)
        tls.handshake()
        suite = tls.ssl.cipher()
        if suite:
            print(f"TLS established: {suite[0]}")

        # 3) Capture loop
        n = 0
        while not stop:
            ctrl_out(dev, CMD_ARM, 0x01, struct.pack("<I", DEFAULT_CAPTURE_ID))
            print("touch the sensor (Ctrl+C to stop)...", flush=True)
            try:
                read_event(dev, EVT_FINGER_DOWN)
            finally:
                # If the user hits Ctrl+C before a finger arrives, make sure we
                # leave the sensor in a clean state for the next run.
                if stop:
                    try_send(dev, CMD_ABORT, 0x01)
                    drain_bulk(dev)

            if stop:
                break

            ctrl_out(dev, CMD_GET_IMG, 0x00)
            evt = tls.read_plain_event()
            if evt.event_id != EVT_IMG or evt.status != 0:
                raise IOError(f"bad image event 0x{evt.event_id:08x} status={evt.status}")
            pixels = evt.data[34:34 + info.width * info.height]

            ctrl_out(dev, CMD_GET_DEAD_PIXEL, 0x00)
            ack = tls.read_plain_event()
            if ack.event_id != EVT_ACK or ack.status != 0:
                raise IOError(f"bad ACK event=0x{ack.event_id:08x} status={ack.status}")

            try_send(dev, CMD_ABORT, 0x01)  # deactivate this capture

            n += 1
            path = next_path(out_dir, args.format)
            save_image(path, args.format, pixels, info)
            print(f"saved {path} (#{n})")
            if args.count and n >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if tls is not None:
            tls.close_notify()
        try_send(dev, CMD_ABORT, 0x01)
        try_send(dev, CMD_INDICATE_S_STATE, 0x11)  # SX sleep
        try:
            usb.util.release_interface(dev, IFACE)
            usb.util.dispose_resources(dev)
        except Exception:
            pass


if __name__ == "__main__":
    main()
