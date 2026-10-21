#!/usr/bin/env python3
# =============================================================================
# test/guac_recording.test.py - the recording format check must not be
# vacuous: it has to PASS a well-formed recording and FAIL every way a
# recording can be broken. Builds small recordings in memory (real PNGs made
# with zlib, Guacamole framing by hand) and runs test/guac_recording.py on
# each through its command line, exactly as test/e2e.sh does.
#
# Prints PASS/FAIL per case (test/run-all.sh counts them); exit 1 on any FAIL.
# Stdlib only, offline. Usage: python3 test/guac_recording.test.py
# =============================================================================
import base64
import json
import os
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "guac_recording.py")
FAILS = 0


def ins(*elems) -> str:
    return ",".join(f"{len(str(e))}.{e}" for e in elems) + ";"


def chunk(ctype: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)


def png(w: int, h: int, width_in_header: int = 0) -> bytes:
    rows = b"".join(b"\x00" + bytes((x * 7 + y * 3) % 256 for x in range(w * 3)) for y in range(h))
    ihdr = struct.pack(">IIBBBBB", width_in_header or w, h, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


def image(stream: str, data: bytes, mime: str = "image/png", layer: str = "0", split: int = 2) -> str:
    b64 = base64.b64encode(data).decode()
    step = max(4, (len(b64) // split) // 4 * 4)
    blobs = "".join(ins("blob", stream, b64[i:i + step]) for i in range(0, len(b64), step))
    return ins("img", stream, "14", layer, mime, "0", "0") + blobs + ins("end", stream)


SCREEN = png(200, 120)
BACKGROUND = ins("rect", "0", "0", "0", "1024", "768") + ins("cfill", "14", "0", "240", "240", "240", "255")
GOOD = (ins("size", "0", "1024", "768") + ins("sync", "1000") + BACKGROUND + image("1", SCREEN)
        + ins("cursor", "0", "0", "-1", "0", "0", "1", "1") + ins("sync", "2500"))


def run(rec: str, *extra):
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "summary.json")
        p = subprocess.run([sys.executable, "-I", TOOL, "--expect-size", "1024x768", "--json-out", out, *extra],
                           input=rec.encode("utf-8"), capture_output=True)
        summary = json.load(open(out)) if p.returncode == 0 and os.path.exists(out) else None
        return p.returncode, p.stderr.decode(), summary


def case(name: str, rec: str, expect_ok: bool, reason: str = "", extra=(), test=None):
    global FAILS
    rc, err, summary = run(rec, *extra)
    ok = (rc == 0) if expect_ok else (rc == 1 and reason in err)
    if ok and test is not None:
        ok = bool(test(summary))
    print(("PASS  " if ok else "FAIL  ") + name)
    if not ok:
        FAILS += 1
        print(f"      exit {rc}: {err.strip()[:300]}")


case("a well-formed recording plays back (1024x768, 2 frames over 1500 ms, a filled screen + one PNG)", GOOD, True,
     test=lambda s: s["layer0_size"] == "1024x768" and s["frames"] == 2 and s["duration_ms"] == 1500
     and s["images"] == {"png": 1} and s["images_on_screen"] == 1 and s["largest_image"] == "200x120"
     and s["screen_painted_pct"] == 100.0)
case("... and its summary carries the recording's sha256 (64 hex), never image data", GOOD, True,
     test=lambda s: len(s["sha256"]) == 64 and "blob" in s["opcodes"] and "iVBOR" not in json.dumps(s)
     and len(json.dumps(s)) < 1200)
case("truncated mid-instruction (the file was cut after a comma) -> does not play back", GOOD[:-7], False, "truncated")
case("truncated mid-element (the file was cut inside a value) -> does not play back", GOOD[:-3], False, "truncated")
case("a corrupted length prefix -> does not play back", "4x.size,1.0,4.1024,3.768;" + GOOD, False, "bad element length")
case("a wrong terminator -> does not play back", GOOD.replace("4.sync,4.1000;", "4.sync,4.1000:", 1), False, "bad terminator")
case("element lengths count Unicode code points: a 4-character name with an accent parses",
     ins("name", "café") + GOOD, True)
case("... and the same name with its UTF-8 byte length (5) does not", "4.name,5.café;" + GOOD, False, "")
bad_b64 = GOOD.replace(ins("end", "1"), ins("blob", "1", "@@@@") + ins("end", "1"))
case("a blob that is not base64 -> does not play back", bad_b64, False, "not valid base64")
broken = bytearray(SCREEN)
broken[-20] ^= 0xFF
case("a PNG whose chunk CRC is wrong -> does not play back",
     ins("size", "0", "1024", "768") + ins("sync", "1") + image("1", bytes(broken)) + ins("sync", "2000"), False, "CRC")
case("a PNG whose pixel data does not match its header (CRCs valid) -> does not play back",
     ins("size", "0", "1024", "768") + ins("sync", "1") + image("1", png(200, 120, width_in_header=201)) + ins("sync", "2000"),
     False, "pixel data")
case("a blob for a stream that was never opened -> does not play back", ins("blob", "9", "AAAA") + GOOD, False, "not open")
case("an end for a stream that was never opened -> does not play back", GOOD + ins("end", "7"), False, "not open")
case("a screen of the wrong size (800x600, 1024x768 expected) -> does not play back",
     GOOD.replace(ins("size", "0", "1024", "768"), ins("size", "0", "800", "600")), False, "expected 1024x768")
case("no size for layer 0 -> does not play back", GOOD.replace(ins("size", "0", "1024", "768"), ""), False, "no size for the default layer 0")
case("no image at all (an empty session) -> does not play back",
     ins("size", "0", "1024", "768") + ins("sync", "1000") + BACKGROUND + ins("sync", "3000"), False, "decodable images")
case("only a 200x120 image on a blank screen (3% painted, 25% needed) -> does not play back",
     ins("size", "0", "1024", "768") + ins("sync", "1000") + image("1", SCREEN) + ins("sync", "3000"), False, "of the 1024x768 screen")
case("images drawn only to an off-screen buffer -> does not play back",
     ins("size", "0", "1024", "768") + ins("sync", "1000") + BACKGROUND + image("1", SCREEN, layer="-1") + ins("sync", "3000"),
     False, "no image was drawn to a visible layer")
case("a fill of an off-screen buffer does not count as screen (only a 200x120 image is visible)",
     ins("size", "0", "1024", "768") + ins("sync", "1000") + ins("rect", "-3", "0", "0", "1024", "768")
     + ins("cfill", "14", "-3", "0", "0", "0", "255") + image("1", SCREEN) + ins("sync", "3000"), False, "3.1% of the 1024x768")
case("... but COPYING that buffer onto the screen does (how RDP glyphs and cached tiles reach layer 0)",
     ins("size", "0", "1024", "768") + ins("sync", "1000") + ins("rect", "-3", "0", "0", "1024", "768")
     + ins("cfill", "14", "-3", "0", "0", "0", "255") + ins("copy", "-3", "0", "0", "1024", "768", "14", "0", "0", "0")
     + image("1", SCREEN) + ins("sync", "3000"), True, test=lambda s: s["screen_painted_pct"] == 100.0)
case("a terminal on a visible child layer (move 1 -> 0 at 2,2; how guacd draws SSH) counts at its screen offset",
     ins("size", "0", "1024", "768") + ins("move", "1", "0", "2", "2", "0") + ins("size", "1", "990", "741")
     + ins("sync", "1000") + ins("rect", "1", "0", "0", "990", "741") + ins("cfill", "14", "1", "0", "0", "0", "255")
     + image("1", SCREEN, layer="1") + ins("sync", "3000"), True,
     test=lambda s: s["images_on_screen"] == 1 and abs(s["screen_painted_pct"] - 93.3) < 0.1)
case("sync timestamps going backwards -> does not play back",
     GOOD.replace(ins("sync", "2500"), ins("sync", "500")), False, "backwards")
case("a session shorter than --min-duration-ms -> does not play back",
     GOOD.replace(ins("sync", "2500"), ins("sync", "1200")), False, "spans 200 ms")
# SOI, a JFIF APP0, an SOF0 frame header for 64x32, EOI (structure only: the check walks markers)
jpeg = (b"\xff\xd8" + b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00" + b"\x00" * 9
        + b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, 32, 64, 1) + b"\x01\x11\x00" + b"\xff\xd9")
case("a JPEG stream (SOI ... EOI) next to the PNG plays back",
     GOOD.replace(ins("sync", "2500"), image("2", jpeg, "image/jpeg") + ins("sync", "2500")), True,
     test=lambda s: s["images"] == {"jpeg": 1, "png": 1})
case("a JPEG without a frame header (SOF) -> does not play back",
     GOOD.replace(ins("sync", "2500"), image("2", b"\xff\xd8\xff\xd9", "image/jpeg") + ins("sync", "2500")), False, "frame header")
case("a JPEG without its EOI -> does not play back",
     GOOD.replace(ins("sync", "2500"), image("2", jpeg[:-2], "image/jpeg") + ins("sync", "2500")), False, "SOI/EOI")
case("an image stream of an unknown type -> does not play back",
     GOOD.replace(ins("sync", "2500"), image("2", b"GIF89a....", "image/gif") + ins("sync", "2500")), False, "unknown type")
rc = subprocess.run([sys.executable, "-I", TOOL], input=b"\xff\xfe", capture_output=True).returncode
print(("PASS  " if rc == 1 else "FAIL  ") + "bytes that are not UTF-8 -> does not play back (exit 1)")
FAILS += rc != 1
rc = subprocess.run([sys.executable, "-I", TOOL], input=b"", capture_output=True).returncode
print(("PASS  " if rc == 1 else "FAIL  ") + "an empty file -> does not play back (exit 1)")
FAILS += rc != 1

print(f"\nguac_recording.py format check: {'all cases behaved' if FAILS == 0 else f'{FAILS} case(s) FAILED'}")
sys.exit(1 if FAILS else 0)
