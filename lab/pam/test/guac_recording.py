#!/usr/bin/env python3
# =============================================================================
# test/guac_recording.py - the GUACAMOLE-RECORDING FORMAT CHECK: does a
# session recording written by guacd play back?
#
# A guacd recording is the session's Guacamole protocol stream, saved as the
# client received it. Guacamole's own History player (guacamole-common-js
# SessionRecording) replays exactly that stream; guacenc turns it into video.
# guacenc is not in the guacamole/guacd 1.6.0 image and Debian trixie does
# not package it, so instead of rendering video this walks the stream the way
# a player does and fails on anything a player would choke on:
#
#   1. Framing: every element is LENGTH.VALUE (length in Unicode code points),
#      elements end with "," or ";", and the file ends on an instruction
#      boundary (a truncated or corrupted file fails here).
#   2. Display: a "size" for the default layer 0, optionally equal to
#      --expect-size (the session's screen, e.g. 1024x768).
#   3. Frames: "sync" timestamps never go backwards; at least --min-frames of
#      them; the session spans at least --min-duration-ms.
#   4. Images: every "img" stream is fed only by "blob"s for streams that are
#      open and closed by "end"; each blob is strict base64; each finished
#      image DECODES - PNG: signature, every chunk's CRC, IHDR, the
#      zlib-inflated IDAT is exactly height x (1 + row bytes) long and every
#      row's filter byte is 0-4; JPEG: SOI, a frame header, EOI; WebP:
#      RIFF/WEBP header. At least --min-images of them, and at least one
#      drawn to a VISIBLE layer (the default layer 0 or a layer >= 1 placed
#      on it with "move"; negative indexes are off-screen buffers).
#   5. Screen: the drawing operations a player would apply to the visible
#      layers (images, solid fills of rectangle paths, copies / transfers
#      from other layers and buffers - how RDP glyphs and the SSH terminal
#      reach the screen), mapped to screen coordinates through each layer's
#      "move" position, paint at least --min-coverage of the layer-0 screen:
#      a session that showed a real screen, not just a cursor. Painted =
#      touched at least once; the pixels themselves are not composited.
#
# Reads the recording on stdin (or a path). Prints a JSON summary (sizes,
# counts, duration, sha256 - never image data) and exits 0 if it plays back,
# 1 if not (the reasons on stderr), 2 on usage errors. Stdlib only.
#   docker compose exec -T guacamole cat /var/lib/guacamole/recordings/<uuid>/recording \
#     | python3 test/guac_recording.py --expect-size 1024x768
# =============================================================================
import argparse
import base64
import binascii
import hashlib
import json
import struct
import sys
import zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"
# bits per pixel by PNG colour type, for bit depth d
PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


class NotPlayable(Exception):
    pass


def parse(text: str):
    """Yield instructions (lists of str) from a Guacamole protocol stream; strict."""
    pos, n = 0, len(text)
    while pos < n:
        elems = []
        while True:
            if pos >= n or (text.find(".", pos, pos + 12) < 0 and text[pos:].isdigit()):
                raise NotPlayable(f"truncated instruction at offset {pos} (file ends mid-instruction)")
            dot = text.find(".", pos, pos + 12)
            if dot < 0 or not text[pos:dot].isdigit():
                raise NotPlayable(f"bad element length at offset {pos}")
            length = int(text[pos:dot])
            start, end = dot + 1, dot + 1 + length
            if end >= n:
                raise NotPlayable(f"truncated instruction at offset {pos} (file ends mid-element)")
            elems.append(text[start:end])
            term = text[end]
            pos = end + 1
            if term == ";":
                break
            if term != ",":
                raise NotPlayable(f"bad terminator {term!r} at offset {end}")
        yield elems


def check_png(data: bytes):
    if not data.startswith(PNG_SIG):
        raise NotPlayable("PNG without its signature")
    pos, idat, ihdr, ended = len(PNG_SIG), [], None, False
    while pos < len(data):
        if pos + 8 > len(data):
            raise NotPlayable("PNG chunk header truncated")
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if len(body) != length or pos + 12 + length > len(data):
            raise NotPlayable(f"PNG chunk {ctype!r} truncated")
        (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
        if zlib.crc32(ctype + body) & 0xFFFFFFFF != crc:
            raise NotPlayable(f"PNG chunk {ctype!r} fails its CRC")
        if ctype == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", body)
        elif ctype == b"IDAT":
            idat.append(body)
        elif ctype == b"IEND":
            ended = True
            break
        pos += 12 + length
    if ihdr is None or not idat or not ended:
        raise NotPlayable("PNG without IHDR / IDAT / IEND")
    w, h, depth, ctype, _comp, _filt, interlace = ihdr
    if w == 0 or h == 0 or ctype not in PNG_CHANNELS or interlace not in (0, 1):
        raise NotPlayable(f"PNG header not valid ({w}x{h}, colour type {ctype})")
    try:
        raw = zlib.decompress(b"".join(idat))
    except zlib.error as e:
        raise NotPlayable(f"PNG image data does not inflate: {e}") from None
    if interlace == 0:
        row = (w * PNG_CHANNELS[ctype] * depth + 7) // 8
        if len(raw) != h * (row + 1):
            raise NotPlayable(f"PNG pixel data is {len(raw)} bytes, {w}x{h} needs {h * (row + 1)}")
        for y in range(h):
            if raw[y * (row + 1)] > 4:
                raise NotPlayable(f"PNG row {y} has an unknown filter type")
    return w, h


def jpeg_size(data: bytes):
    """Width x height from the first SOFn frame header (markers walked, no decoding)."""
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            raise NotPlayable("JPEG marker structure broken")
        marker = data[pos + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        (seglen,) = struct.unpack(">H", data[pos + 2:pos + 4])
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            if pos + 9 > len(data):
                break
            h, w = struct.unpack(">HH", data[pos + 5:pos + 9])
            if w and h:
                return w, h
            break
        if marker == 0xDA:          # start of scan before any frame header
            break
        pos += 2 + seglen
    raise NotPlayable("JPEG without a frame header (SOF)")


def webp_size(data: bytes):
    fourcc = data[12:16]
    if fourcc == b"VP8X" and len(data) >= 30:
        return 1 + int.from_bytes(data[24:27], "little"), 1 + int.from_bytes(data[27:30], "little")
    if fourcc == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
        w, h = struct.unpack("<HH", data[26:30])
        return w & 0x3FFF, h & 0x3FFF
    if fourcc == b"VP8L" and len(data) >= 25 and data[20] == 0x2F:
        bits = int.from_bytes(data[21:25], "little")
        return 1 + (bits & 0x3FFF), 1 + ((bits >> 14) & 0x3FFF)
    raise NotPlayable("WebP without a VP8 / VP8L / VP8X header")


def check_image(mime: str, data: bytes):
    if mime == "image/png":
        return check_png(data)
    if mime == "image/jpeg":
        if not (data[:2] == b"\xff\xd8" and data[-2:] == b"\xff\xd9"):
            raise NotPlayable("JPEG without SOI/EOI")
        return jpeg_size(data)
    if mime == "image/webp":
        if not (data[:4] == b"RIFF" and data[8:12] == b"WEBP"):
            raise NotPlayable("WebP without its RIFF/WEBP header")
        return webp_size(data)
    raise NotPlayable(f"image stream of unknown type {mime!r}")


def coverage(rects, size) -> float:
    """Share of the layer-0 pixels touched by at least one painted rectangle."""
    w, h = size
    if w <= 0 or h <= 0:
        return 0.0
    painted, ones = bytearray(w * h), b"\x01" * w
    for x, y, rw, rh in rects:
        x0, y0, x1, y1 = max(0, x), max(0, y), min(w, x + rw), min(h, y + rh)
        if x1 <= x0 or y1 <= y0:
            continue
        for row in range(y0, y1):
            painted[row * w + x0:row * w + x1] = ones[:x1 - x0]
    return painted.count(1) / (w * h)


def verify(raw: bytes, args) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise NotPlayable(f"not UTF-8 text: {e}") from None
    ops, syncs, sizes = {}, [], {}
    streams = {}             # stream index -> {"kind", "mime", "layer", "x", "y", "chunks"}
    images = {"image/png": 0, "image/jpeg": 0, "image/webp": 0}
    largest, visible_images, n = (0, 0), 0, 0
    paths = {}               # layer -> rectangles of its current path (rect ... then cfill / lfill)
    painted = []             # rectangles drawn to the screen: (x, y, w, h) in layer-0 coordinates
    placed = {}              # visible layer >= 1 -> (parent, x, y) from "move"

    def origin(layer: str, depth: int = 0):
        """Screen offset of a visible layer, or None for a buffer / an unplaced layer."""
        if layer == "0":
            return (0, 0)
        if depth > 32 or layer.startswith("-") or layer not in placed:
            return None
        parent, x, y = placed[layer]
        base = origin(parent, depth + 1)
        return None if base is None else (base[0] + x, base[1] + y)

    def paint(layer: str, x: int, y: int, w: int, h: int) -> bool:
        o = origin(layer)
        if o is not None:
            painted.append((o[0] + x, o[1] + y, w, h))
        return o is not None

    def num(v: str) -> int:
        try:
            return int(v)
        except ValueError:
            raise NotPlayable(f"{op} with a non-numeric argument {v!r}") from None
    for ins in parse(text):
        n += 1
        op, a = ins[0], ins[1:]
        ops[op] = ops.get(op, 0) + 1
        if op == "size" and len(a) >= 3:
            sizes[a[0]] = (int(a[1]), int(a[2]))
        elif op == "sync":
            if not a or not a[0].lstrip("-").isdigit():
                raise NotPlayable("sync without a timestamp")
            ts = int(a[0])
            if syncs and ts < syncs[-1]:
                raise NotPlayable(f"sync timestamps go backwards ({syncs[-1]} -> {ts})")
            syncs.append(ts)
        elif op == "img":
            if len(a) < 6:
                raise NotPlayable("img instruction with too few arguments")
            if a[0] in streams:
                raise NotPlayable(f"img reuses stream {a[0]} before its end")
            streams[a[0]] = {"kind": "img", "mime": a[3], "layer": a[2], "x": num(a[4]), "y": num(a[5]), "chunks": []}
        elif op == "move" and len(a) >= 4:
            placed[a[0]] = (a[1], num(a[2]), num(a[3]))
        elif op == "dispose" and a:
            placed.pop(a[0], None)
            paths.pop(a[0], None)
        elif op == "rect" and len(a) >= 5:
            paths.setdefault(a[0], []).append((num(a[1]), num(a[2]), num(a[3]), num(a[4])))
        elif op in ("cfill", "lfill") and len(a) >= 2:
            for r in paths.pop(a[1], []):
                paint(a[1], *r)
        elif op in ("cstroke", "lstroke") and len(a) >= 2:
            paths.pop(a[1], None)
        elif op in ("copy", "transfer") and len(a) >= 9:
            # copy SRC sx sy w h MASK DST dx dy / transfer SRC sx sy w h FUNCTION DST dx dy
            paint(a[6], num(a[7]), num(a[8]), num(a[3]), num(a[4]))
        elif op in ("audio", "file", "pipe", "argv", "clipboard", "video"):
            if a:
                streams[a[0]] = {"kind": op, "mime": a[1] if len(a) > 1 else "", "layer": None, "chunks": None}
        elif op == "blob":
            if len(a) != 2 or a[0] not in streams:
                raise NotPlayable(f"blob for a stream that is not open ({a[0] if a else '?'})")
            try:
                chunk = base64.b64decode(a[1], validate=True)
            except (binascii.Error, ValueError):
                raise NotPlayable(f"blob for stream {a[0]} is not valid base64") from None
            if streams[a[0]]["chunks"] is not None:
                streams[a[0]]["chunks"].append(chunk)
        elif op == "end":
            if not a or a[0] not in streams:
                raise NotPlayable(f"end for a stream that is not open ({a[0] if a else '?'})")
            st = streams.pop(a[0])
            if st["kind"] == "img":
                dims = check_image(st["mime"], b"".join(st["chunks"]))
                images[st["mime"]] = images.get(st["mime"], 0) + 1
                if paint(st["layer"], st["x"], st["y"], dims[0], dims[1]):
                    visible_images += 1
                if dims[0] * dims[1] > largest[0] * largest[1]:
                    largest = dims
    if n == 0:
        raise NotPlayable("empty recording")
    if "0" not in sizes:
        raise NotPlayable("no size for the default layer 0 (a player has no screen to draw on)")
    if args.expect_size and "%dx%d" % sizes["0"] != args.expect_size:
        raise NotPlayable(f"layer 0 is {sizes['0'][0]}x{sizes['0'][1]}, expected {args.expect_size}")
    duration = (syncs[-1] - syncs[0]) if syncs else 0
    if len(syncs) < args.min_frames:
        raise NotPlayable(f"{len(syncs)} frames (sync), need at least {args.min_frames}")
    if duration < args.min_duration_ms:
        raise NotPlayable(f"session spans {duration} ms, need at least {args.min_duration_ms}")
    total = sum(images.values())
    if total < args.min_images:
        raise NotPlayable(f"{total} decodable images, need at least {args.min_images}")
    if args.min_images and visible_images == 0:
        raise NotPlayable("no image was drawn to a visible layer")
    covered = coverage(painted, sizes["0"])
    if covered < args.min_coverage:
        raise NotPlayable(f"drawing reaches {covered:.1%} of the {sizes['0'][0]}x{sizes['0'][1]} screen, "
                          f"need at least {args.min_coverage:.0%} (a real screen, not just a cursor)")
    return {
        "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "instructions": n,
        "layer0_size": "%dx%d" % sizes["0"], "frames": len(syncs), "duration_ms": duration,
        "images": {k.split("/")[1]: v for k, v in images.items() if v}, "images_on_screen": visible_images,
        "largest_image": "%dx%d" % largest, "screen_painted_pct": round(covered * 100, 1),
        "draw_ops_on_screen": len(painted), "open_streams_at_end": len(streams),
        "opcodes": dict(sorted(ops.items())),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Guacamole recording format check (does it play back?)")
    ap.add_argument("path", nargs="?", help="recording file (default: stdin)")
    ap.add_argument("--expect-size", default="", help="WxH of layer 0, e.g. 1024x768")
    ap.add_argument("--min-frames", type=int, default=2)
    ap.add_argument("--min-duration-ms", type=int, default=1000)
    ap.add_argument("--min-images", type=int, default=1)
    ap.add_argument("--min-coverage", type=float, default=0.25,
                    help="share of the layer-0 screen the session must paint (0-1)")
    ap.add_argument("--json-out", default="", help="also write the summary JSON here")
    args = ap.parse_args()
    raw = open(args.path, "rb").read() if args.path else sys.stdin.buffer.read()
    try:
        summary = verify(raw, args)
    except NotPlayable as e:
        print(f"guac_recording: does NOT play back: {e}", file=sys.stderr)
        return 1
    out = json.dumps(summary, indent=2, sort_keys=True)
    print(out)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
