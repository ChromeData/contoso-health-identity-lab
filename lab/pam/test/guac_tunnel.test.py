#!/usr/bin/env python3
# =============================================================================
# test/guac_tunnel.test.py - test/guac_tunnel.py decides whether a scripted
# Guacamole session "ran and the server ended it" (test/e2e.sh's SSH and RDP
# session checks rest on that verdict), so its rules are tested here, offline,
# against a FAKE Guacamole HTTP tunnel (stdlib http.server on 127.0.0.1)
# that streams scripted instructions and records what the client sends:
#
#   * the server ends the session after the Return -> exit 0
#   * guacd reports that end as an error with an ACCEPTED status
#     (--server-close-status), after the Return -> exit 0, status named;
#     the same without the flag -> exit 2 (strict by default)
#   * an accepted status BEFORE the keys were typed -> exit 2, nothing typed
#   * any other status after the Return -> exit 2
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
    """One scripted tunnel. on_return / up_front: instructions to stream at that moment.

    end_after_return=False: the stream stays open (a session that never ends).
    """

    def __init__(self, up_front="", on_return="", end_after_return=True):
        self.up_front, self.on_return, self.end_after_return = up_front, on_return, end_after_return
        self.writes = []                     # (time, body) of every ?write
        self.returned = threading.Event()
        self.stop = threading.Event()

    def keys(self):
        return "".join(b for _, b in self.writes if "3.key," in b)


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
            self.wfile.write((ins("size", "0", "1024", "768") + ins("sync", "1000") + fake.up_front).encode())
            self.wfile.flush()
            if fake.up_front and "5.error" in fake.up_front:
                self.wfile.write(b"0.;")     # guacd stopped: the servlet ends the stream
                return
            while not fake.returned.wait(0.1):
                if fake.stop.is_set():
                    return
            if not fake.end_after_return:
                fake.stop.wait(30)
                return
            time.sleep(0.2)                  # the command runs, then the session ends
            self.wfile.write((ins("sync", "2000") + fake.on_return + "0.;").encode())
            self.wfile.flush()

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


UPSTREAM_GONE = ins("error", "Aborted. See logs.", "520")         # 0x0208 UPSTREAM_UNAVAILABLE
FORBIDDEN = ins("error", "Aborted. See logs.", "771")             # 0x0303 CLIENT_FORBIDDEN

f = Fake()
rc, out = run(f)
case("the server ends the session after the Return (no error) -> exit 0, 'the server ended it'",
     rc == 0 and "the server ended it" in out and f.keys(), out)

f = Fake(on_return=UPSTREAM_GONE)
rc, out = run(f, "--server-close-status", "UPSTREAM_UNAVAILABLE")
case("guacd reports the end as 0x0208 UPSTREAM_UNAVAILABLE after the Return, status accepted -> exit 0, status named",
     rc == 0 and "the server ended it" in out and "0x0208 UPSTREAM_UNAVAILABLE" in out, out)

f = Fake(on_return=UPSTREAM_GONE)
rc, out = run(f, "--server-close-status", "0x0208")
case("--server-close-status takes the hex code as well as the name", rc == 0 and "the server ended it" in out, out)

f = Fake(on_return=UPSTREAM_GONE)
rc, out = run(f)
case("the same error without --server-close-status -> exit 2 (strict by default; SSH runs this way)",
     rc == 2 and "the server ended it" not in out and "0x0208 UPSTREAM_UNAVAILABLE" in out, out)

f = Fake(up_front=UPSTREAM_GONE)
rc, out = run(f, "--server-close-status", "UPSTREAM_UNAVAILABLE")
case("an accepted status BEFORE the keys were typed -> exit 2 and nothing typed (a session that never ran)",
     rc == 2 and "before the keys were typed" in out and not f.keys(), out)

f = Fake(on_return=FORBIDDEN)
rc, out = run(f, "--server-close-status", "UPSTREAM_UNAVAILABLE")
case("any other status after the Return (0x0303 CLIENT_FORBIDDEN) -> exit 2",
     rc == 2 and "0x0303 CLIENT_FORBIDDEN" in out and "the server ended it" not in out, out)

f = Fake(end_after_return=False)
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

f = Fake()
rc, out = run(f, "--ready-cmd", f"{sys.executable} -I -c \"import sys; print('no marker yet', file=sys.stderr); sys.exit(1)\"",
              timeout="3")
case("--ready-cmd never succeeds -> exit 3 'never became ready' with the last check's output, nothing typed",
     rc == 3 and "never became ready" in out and "no marker yet" in out and not f.keys(), out)

f = Fake()
rc, out = run(f, token="wrong-token")
case("a refused connect (HTTP 403) -> exit 2 'connect refused'", rc == 2 and "connect refused" in out, out)

p = subprocess.run([sys.executable, "-I", TOOL, "--base", "http://127.0.0.1:9/guacamole", "--connection-id", "1",
                    "--server-close-status", "SUCCESS"], input=b"x", capture_output=True)
case("--server-close-status SUCCESS is refused (guacd never sends SUCCESS as an error)", p.returncode == 2,
     p.stderr.decode())

print(f"\nguac_tunnel.py session verdicts: {'all cases behaved' if FAILS == 0 else f'{FAILS} case(s) FAILED'}")
sys.exit(1 if FAILS else 0)
