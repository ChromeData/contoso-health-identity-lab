#!/usr/bin/env python3
# =============================================================================
# test/guac_tunnel.py - drive ONE real Guacamole session without a browser,
# for test/e2e.sh: proves an operator's READ permission is enough to CONNECT,
# and produces a genuine recorded session (typescript + graphical recording,
# written by guacd exactly as for a browser session).
#
# Speaks Guacamole's HTTP tunnel (the fallback transport guacamole-common-js
# uses when WebSockets are unavailable):
#   POST <base>/tunnel?connect           body: token, GUAC_ID, GUAC_TYPE=c, ...
#        -> tunnel UUID (body) + Guacamole-Tunnel-Token header (1.5+)
#   GET  <base>/tunnel?read:<uuid>:<n>   one long streaming response of
#        instructions, ending with "0.;" when the tunnel closes
#   POST <base>/tunnel?write:<uuid>      instructions from the client
# Every "sync" from guacd is answered with the same timestamp (as the JS
# client does), key presses are sent as X11 keysyms, and an "error"
# instruction ends the run with its message and exit code 2.
# Works for SSH and RDP alike (the tunnel is protocol-agnostic). For RDP:
# --mouse X,Y moves the pointer first (the xrdp stand-in has no window
# manager, so keyboard focus follows the pointer), and --settle is longer
# (TLS + Kerberos logon + Xorg start). --disconnect-after N: if the server
# has not ended the session N seconds after the keys were typed, the client
# sends "disconnect" itself (reported as such, exit 0) - the session is still
# recorded up to that point.
#
# Stdlib only. The operator's Guacamole auth token is read from stdin (never
# argv). Usage:
#   printf '%s' "$TOKEN" | python3 test/guac_tunnel.py --base http://127.0.0.1:8081/guacamole \
#       --connection-id 3 --type "id; hostname; exit"
#   (RDP: ... --connection-id 5 --mouse 512,384 --settle 12 --type "id > proof; exit")
# Exit: 0 tunnel opened, keys sent, session ended cleanly; 2 Guacamole error;
#       3 timeout / no data.
# =============================================================================
import argparse
import http.client
import sys
import threading
import time
import urllib.parse

KEYSYM_RETURN = 0xFF0D

# Guacamole protocol status codes (guacamole-server 1.6.0,
# src/libguac/guacamole/protocol-types.h, enum guac_protocol_status), so an
# "error" instruction is reported by name, not as a bare decimal.
STATUS_NAMES = {
    0x0000: "SUCCESS", 0x0100: "UNSUPPORTED", 0x0200: "SERVER_ERROR", 0x0201: "SERVER_BUSY",
    0x0202: "UPSTREAM_TIMEOUT", 0x0203: "UPSTREAM_ERROR", 0x0204: "RESOURCE_NOT_FOUND",
    0x0205: "RESOURCE_CONFLICT", 0x0206: "RESOURCE_CLOSED", 0x0207: "UPSTREAM_NOT_FOUND",
    0x0208: "UPSTREAM_UNAVAILABLE", 0x0209: "SESSION_CONFLICT", 0x020A: "SESSION_TIMEOUT",
    0x020B: "SESSION_CLOSED", 0x0300: "CLIENT_BAD_REQUEST", 0x0301: "CLIENT_UNAUTHORIZED",
    0x0303: "CLIENT_FORBIDDEN", 0x0308: "CLIENT_TIMEOUT", 0x030D: "CLIENT_OVERRUN",
    0x030F: "CLIENT_BAD_TYPE", 0x031D: "CLIENT_TOO_MANY",
}


def describe_status(code: str) -> str:
    """'520' -> '0x0208 UPSTREAM_UNAVAILABLE' (the instruction carries the code in decimal)."""
    try:
        n = int(code)
    except ValueError:
        return f"status {code!r}"
    return f"0x{n:04X} {STATUS_NAMES.get(n, 'UNKNOWN')}"


def encode(*elements: str) -> str:
    # Guacamole instruction: LENGTH.VALUE elements, comma-separated, ";" ends it.
    # LENGTH counts Unicode code points, not bytes.
    return ",".join(f"{len(e)}.{e}" for e in elements) + ";"


class Parser:
    """Incremental instruction parser (handles instructions split across reads)."""

    def __init__(self):
        self.buf = ""

    def feed(self, text: str):
        self.buf += text
        out = []
        while True:
            elems, pos, done = [], 0, False
            while True:
                dot = self.buf.find(".", pos)
                if dot < 0:
                    break
                length = int(self.buf[pos:dot])
                start, end = dot + 1, dot + 1 + length
                if end >= len(self.buf):
                    break
                elems.append(self.buf[start:end])
                term = self.buf[end]
                pos = end + 1
                if term == ";":
                    done = True
                    break
            if not done:
                return out
            self.buf = self.buf[pos:]
            out.append(elems)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="http://127.0.0.1:8081/guacamole")
    ap.add_argument("--connection-id", required=True)
    ap.add_argument("--data-source", default="postgresql")
    ap.add_argument("--type", dest="text", default="", help="text to type; '; exit' style, Return appended")
    ap.add_argument("--settle", type=float, default=4.0, help="seconds to wait for the shell before typing")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--mouse", default="", help="X,Y: move the pointer there before typing")
    ap.add_argument("--disconnect-after", type=float, default=0.0,
                    help="seconds after typing to wait for the server to end the session before disconnecting")
    args = ap.parse_args()

    token = sys.stdin.read().strip()
    if not token:
        print("guac_tunnel: no auth token on stdin", file=sys.stderr)
        return 3
    base = urllib.parse.urlparse(args.base)
    path = base.path.rstrip("/") + "/tunnel"

    def conn():
        return http.client.HTTPConnection(base.hostname, base.port or 80, timeout=args.timeout)

    form = [("token", token), ("GUAC_DATA_SOURCE", args.data_source), ("GUAC_ID", args.connection_id),
            ("GUAC_TYPE", "c"), ("GUAC_WIDTH", "1024"), ("GUAC_HEIGHT", "768"), ("GUAC_DPI", "96"),
            ("GUAC_TIMEZONE", "UTC"), ("GUAC_IMAGE", "image/png")]
    c = conn()
    c.request("POST", path + "?connect", body=urllib.parse.urlencode(form),
              headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
    r = c.getresponse()
    body = r.read().decode(errors="replace").strip()
    if r.status != 200:
        print(f"guac_tunnel: connect refused (HTTP {r.status}, Guacamole-Error-Message: "
              f"{r.getheader('Guacamole-Error-Message', '-')})", file=sys.stderr)
        return 2
    uuid, tunnel_token = body, r.getheader("Guacamole-Tunnel-Token", "")
    hdrs = {"Guacamole-Tunnel-Token": tunnel_token} if tunnel_token else {}

    state = {"error": None, "error_at": None, "closed": False, "instructions": 0, "first": None, "typed_at": None}
    lock = threading.Lock()
    writer = conn()

    def write(data: str):
        with lock:
            writer.request("POST", f"{path}?write:{uuid}", body=data.encode(),
                           headers=dict(hdrs, **{"Content-Type": "application/octet-stream"}))
            resp = writer.getresponse()
            resp.read()

    def reader():
        rc = conn()
        rc.request("GET", f"{path}?read:{uuid}:0", headers=hdrs)
        resp = rc.getresponse()
        parser = Parser()
        while True:
            chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(4096)
            if not chunk:
                break
            for ins in parser.feed(chunk.decode(errors="replace")):
                state["instructions"] += 1
                if state["first"] is None:
                    state["first"] = time.time()
                op = ins[0] if ins else ""
                if op == "":
                    continue                      # end-of-response marker / internal
                if op == "sync" and len(ins) > 1:
                    try:
                        write(encode("sync", ins[1]))
                    except OSError:
                        pass
                elif op == "error":
                    msg, code = (ins[1] if len(ins) > 1 else ""), (ins[2] if len(ins) > 2 else "")
                    state["error"] = f"{msg!r} {describe_status(code)}"
                    state["error_at"] = time.time()
                elif op == "disconnect":
                    state["closed"] = True
        state["closed"] = True

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    deadline = time.time() + args.timeout
    while state["first"] is None and time.time() < deadline and not state["closed"]:
        time.sleep(0.2)
    if state["first"] is None:
        print("guac_tunnel: no data from the tunnel", file=sys.stderr)
        return 3
    time.sleep(args.settle)                      # let the SSH login and prompt render
    if state["error"]:
        print(f"guac_tunnel: Guacamole error: {state['error']}", file=sys.stderr)
        return 2
    if args.mouse:
        x, y = (str(int(v)) for v in args.mouse.split(","))
        write(encode("mouse", x, y, "0"))
        time.sleep(0.3)
    for ch in args.text:
        ks = ord(ch)                             # Latin-1 printable: keysym == code point
        write(encode("key", str(ks), "1") + encode("key", str(ks), "0"))
        time.sleep(0.02)
    if args.text:
        write(encode("key", str(KEYSYM_RETURN), "1") + encode("key", str(KEYSYM_RETURN), "0"))

    typed_at = time.time()
    state["typed_at"] = typed_at
    client_disconnect = False
    while not state["closed"] and time.time() < deadline:
        if args.disconnect_after and time.time() - typed_at > args.disconnect_after:
            write(encode("disconnect"))
            client_disconnect = True
            end_wait = time.time() + 10
            while not state["closed"] and time.time() < end_wait:
                time.sleep(0.2)
            state["closed"] = True
            break
        time.sleep(0.2)
    if state["error"]:
        when = ("before the keys were typed" if state["error_at"] < typed_at
                else f"{state['error_at'] - typed_at:.1f}s after the keys were typed")
        print(f"guac_tunnel: Guacamole error {when}: {state['error']}", file=sys.stderr)
        return 2
    if not state["closed"]:
        print("guac_tunnel: session did not end before the timeout", file=sys.stderr)
        return 3
    how = "client sent disconnect" if client_disconnect else "the server ended it"
    print(f"guac_tunnel: session ran and ended ({how}; {state['instructions']} instructions received)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
