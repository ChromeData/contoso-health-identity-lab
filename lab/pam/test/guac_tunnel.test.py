#!/usr/bin/env python3
# =============================================================================
# test/guac_tunnel.test.py - test/guac_tunnel.py decides whether a scripted
# Guacamole session "ran and the server ended it" (test/e2e.sh's SSH and RDP
# session checks rest on that verdict), so its rules are tested here, offline,
# against a FAKE Guacamole HTTP tunnel (stdlib http.server on 127.0.0.1)
# that streams scripted instructions and records what the client sends:
#
#   * the server ends the session after the Return -> exit 0
#   * the session stops after the client's last sync reply and, like guacd
#     1.6.0's user input thread, the fake closes the tunnel only on the
#     client's NEXT instruction (else CLIENT_TIMEOUT): the 5 s "nop"
#     keep-alive ends it cleanly -> exit 0 (the nightly RDP failure)
#   * keep-alive "nop"s also go out while waiting for --ready-cmd
#   * an error after the Return (CLIENT_TIMEOUT) -> exit 2, status named
#   * an error before the keys were typed -> exit 2, nothing typed; an
#     error or a clean close WHILE typing stops the typing (no Return):
#     exit 2 / exit 3 "never ran", never "the server ended it"
#   * the session never ends -> exit 3
#   * --ready-cmd: nothing is typed until it succeeds; never ready -> exit 3,
#     nothing typed
#   * a refused connect -> exit 2
#
# Runs test/guac_tunnel.py through its command line, as test/e2e.sh does.
# Prints PASS/FAIL per case (test/run-all.sh counts them); exit 1 on any FAIL.
# Stdlib only, offline. Usage: python3 test/guac_tunnel.test.py
# =============================================================================
import http.server
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "guac_tunnel.py")
TOKEN = "test-token"
RETURN_DOWN = "3.key,5.65293,1.1;"
FAILS = 0


def ins(*elems) -> str:
    return ",".join(f"{len(str(e))}.{e}" for e in elems) + ";"


class Fake:
    """One scripted tunnel. up_front: instructions streamed at once; then, after the Return:

    end="close"  - a last sync, on_return, then the stream ends (session over);
    end="guacd"  - a last sync; once the client has answered it the session is
                   STOPPED, and (as guacd's user input thread does) the tunnel
                   closes on the client's next instruction, or after
                   user_timeout seconds with "error ... CLIENT_TIMEOUT";
    end="never"  - the stream stays open.
    """

    def __init__(self, up_front="", on_return="", end="close", user_timeout=8.0, up_front_delay=0.0):
        self.up_front, self.on_return, self.end, self.user_timeout = up_front, on_return, end, user_timeout
        self.up_front_delay = up_front_delay     # seconds between the first instructions and up_front
        self.writes = []                     # (time, body) of every ?write
        self.returned = threading.Event()
        self.stop = threading.Event()
        self.stopped_at = None

    def keys(self):
        return "".join(b for _, b in self.writes if "3.key," in b)

    def first_key_at(self):
        return min((t for t, b in self.writes if "3.key," in b), default=None)

    def nops(self):
        return [t for t, b in self.writes if "3.nop;" in b]


def serve(fake: Fake):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"        # close-delimited streaming read, like a servlet stream

        def log_message(self, *a):
            pass

        def do_POST(self):
            q = urllib.parse.urlparse(self.path).query
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            if q == "connect":
                if urllib.parse.parse_qs(body).get("token") != [TOKEN]:
                    self.send_response(403)
                    self.send_header("Guacamole-Error-Message", "Permission denied.")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                out = b"tunnel-1"
                self.send_response(200)
                self.send_header("Guacamole-Tunnel-Token", "tt")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
                return
            fake.writes.append((time.time(), body))
            if RETURN_DOWN in body:
                fake.returned.set()
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write((ins("size", "0", "1024", "768") + ins("sync", "1000")).encode())
            self.wfile.flush()
            if fake.up_front:
                time.sleep(fake.up_front_delay)
                self.wfile.write(fake.up_front.encode())
                self.wfile.flush()
            if fake.up_front and ("5.error" in fake.up_front or "10.disconnect" in fake.up_front):
                self.wfile.write(b"0.;")     # guacd stopped: the servlet ends the stream
                return
            while not fake.returned.wait(0.1):
                if fake.stop.is_set():
                    return
            if fake.end == "never":
                fake.stop.wait(30)
                return
            time.sleep(0.2)                  # the command runs, then the session ends
            if fake.end == "close":
                self.wfile.write((ins("sync", "2000") + fake.on_return + "0.;").encode())
                self.wfile.flush()
                return
            # end == "guacd": the last frame, its reply, then the session stops
            self.wfile.write(ins("sync", "2000").encode())
            self.wfile.flush()
            t0 = time.time()
            while time.time() - t0 < 2 and not any("4.sync,4.2000;" in b for _, b in fake.writes):
                time.sleep(0.02)
            fake.stopped_at = time.time()
            while time.time() - fake.stopped_at < fake.user_timeout:
                if any(t > fake.stopped_at for t, _ in fake.writes):
                    self.wfile.write(b"0.;")         # next instruction read: user leaves, tunnel closes
                    return
                time.sleep(0.05)
            self.wfile.write((ins("error", "Aborted. See logs.", "776") + "0.;").encode())   # 0x0308

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run(fake: Fake, *extra, token=TOKEN, timeout="8"):
    srv = serve(fake)
    try:
        p = subprocess.run([sys.executable, "-I", TOOL, "--base", f"http://127.0.0.1:{srv.server_address[1]}/guacamole",
                            "--connection-id", "1", "--settle", "0", "--type", "exit", "--timeout", timeout, *extra],
                           input=token.encode(), capture_output=True, timeout=60)
        return p.returncode, p.stdout.decode() + p.stderr.decode()
    finally:
        fake.stop.set()
        srv.shutdown()


def case(name, ok, out=""):
    global FAILS
    print(("PASS  " if ok else "FAIL  ") + name)
    if not ok:
        FAILS += 1
        for line in out.strip().splitlines()[-6:]:
            print("      " + line)


CLIENT_TIMEOUT = ins("error", "Aborted. See logs.", "776")       # 0x0308 CLIENT_TIMEOUT

f = Fake()
rc, out = run(f)
case("the server ends the session after the Return (no error) -> exit 0, 'the server ended it'",
     rc == 0 and "the server ended it" in out and f.keys(), out)

f = Fake(end="guacd")
rc, out = run(f, timeout="20")
case("session stops after the last sync reply; guacd closes on the next instruction: the 5 s 'nop' keep-alive "
     "ends it cleanly -> exit 0 (no CLIENT_TIMEOUT)",
     rc == 0 and "the server ended it" in out and f.stopped_at is not None
     and any(t > f.stopped_at for t in f.nops()), out)

f = Fake(on_return=CLIENT_TIMEOUT)
rc, out = run(f)
case("an error after the Return (0x0308 CLIENT_TIMEOUT) -> exit 2, status named, 'after the keys were typed'",
     rc == 2 and "0x0308 CLIENT_TIMEOUT" in out and "after the keys were typed" in out
     and "the server ended it" not in out, out)

# The error arrives 0.3 s after the first instructions and the client would
# type at 1 s: deterministic, unlike an error in the very first chunk.
f = Fake(up_front=CLIENT_TIMEOUT, up_front_delay=0.3)
rc, out = run(f, "--settle", "1")
case("an error BEFORE the keys were typed -> exit 2 and nothing typed (a session that never ran)",
     rc == 2 and "before the keys were typed" in out and not f.keys(), out)

f = Fake(up_front=ins("disconnect"), up_front_delay=0.4)
rc, out = run(f, "--type", "x" * 200)
case("a clean close (no error) WHILE typing -> exit 3 'never ran', no Return sent (not 'the server ended it')",
     rc == 3 and "the typed command never ran" in out and "the server ended it" not in out
     and RETURN_DOWN not in "".join(b for _, b in f.writes), out)

f = Fake(up_front=CLIENT_TIMEOUT, up_front_delay=0.4)
rc, out = run(f, "--type", "x" * 200)
case("an error while typing -> typing stops at once (no keys into a dead session), exit 2",
     rc == 2 and "while the keys were being typed" in out and 0 < f.keys().count("3.key,") < 2 * 200, out)

f = Fake(end="never")
rc, out = run(f, timeout="3")
case("the session never ends -> exit 3 'did not end before the timeout'",
     rc == 3 and "did not end before the timeout" in out, out)

with tempfile.TemporaryDirectory() as d:
    marker = os.path.join(d, "ready")
    made = {}

    def make_marker():
        time.sleep(1.5)
        try:
            open(marker, "w").close()
            made["at"] = time.time()
        except OSError:
            pass                             # the client already gave up and the folder is gone: the case fails

    threading.Thread(target=make_marker, daemon=True).start()
    f = Fake()
    rc, out = run(f, "--ready-cmd", f"{sys.executable} -I -c \"import os,sys; sys.exit(0 if os.path.exists({marker!r}) else 1)\"")
    first_key = min((t for t, b in f.writes if "3.key," in b), default=None)
    case("--ready-cmd: nothing typed until it succeeds, then typed and 'target ready after' logged -> exit 0",
         rc == 0 and "target ready after" in out and first_key is not None and "at" in made and first_key >= made["at"], out)

with tempfile.TemporaryDirectory() as d:
    marker = os.path.join(d, "ready")
    threading.Timer(6.5, lambda: open(marker, "w").close()).start()
    f = Fake()
    rc, out = run(f, "--ready-cmd", f"{sys.executable} -I -c \"import os,sys; sys.exit(0 if os.path.exists({marker!r}) else 1)\"",
                  timeout="20")
    fk = f.first_key_at()
    case("keep-alive 'nop' goes out while waiting 6.5 s for --ready-cmd (guacd would drop a silent client at 15 s)",
         rc == 0 and fk is not None and any(t < fk for t in f.nops()), out)

f = Fake()
rc, out = run(f, "--ready-cmd", f"{sys.executable} -I -c \"import sys; print('no marker yet', file=sys.stderr); sys.exit(1)\"",
              timeout="3")
case("--ready-cmd never succeeds -> exit 3 'never became ready' with the last check's output, nothing typed",
     rc == 3 and "never became ready" in out and "no marker yet" in out and not f.keys(), out)

f = Fake()
rc, out = run(f, token="wrong-token")
case("a refused connect (HTTP 403) -> exit 2 'connect refused'", rc == 2 and "connect refused" in out, out)

print(f"\nguac_tunnel.py session verdicts: {'all cases behaved' if FAILS == 0 else f'{FAILS} case(s) FAILED'}")
sys.exit(1 if FAILS else 0)
