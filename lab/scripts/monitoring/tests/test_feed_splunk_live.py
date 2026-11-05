"""
Offline tests for lab/scripts/monitoring/feed-splunk-live.py (the Splunk live feed).

No tenant, no Splunk, no Keychain, no launchd: Log Analytics is a fake query
function, HEC is a real HTTP server on 127.0.0.1 (so the poster's real status /
body handling is exercised), and `security` is mocked. Run:

    python3 -I -m unittest discover -s lab/scripts/monitoring/tests -p 'test_feed_splunk_live.py' -v

What they pin (each would fail against a feed without the behaviour):
  * watermark: first run starts at now - backfill; later runs at watermark - overlap;
    the watermark is the newest ingestion_time SENT, compared exactly (7 digits)
  * de-dup: a row returned again inside the overlap is never sent twice; old ids are pruned
  * HEC errors fail loudly: non-200, 200 without code 0, unreachable; the watermark only
    covers ACCEPTED batches; no heartbeat after a failed table; only 503 / refused is
    retried; a batch whose fate is unknown (reply lost, 4xx part-way) is never resent
    blindly: the next run asks Splunk which ids it holds and sends only the others
  * a Log Analytics result marked partial is refused whole
  * the HEC token never appears in output or in an error
  * the row transform matches the replay (JSON-text columns parsed, "[EXT] ..." kept,
    system columns dropped, _time = TimeGenerated, detection columns first)
  * the LaunchAgent template renders to a valid plist, every 300 s, no placeholder left
  * the preflight verdict: fails at 15 minutes, and when there is no heartbeat at all
"""
import contextlib
import datetime as dt
import fcntl
import http.server
import importlib.util
import io
import json
import os
import plistlib
import re
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "feed-splunk-live.py"
spec = importlib.util.spec_from_file_location("feed_splunk_live", str(SCRIPT))
feed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feed)

TOKEN = "11111111-2222-4333-8444-555555555555"
NOW = dt.datetime(2026, 11, 5, 16, 0, 0, tzinfo=dt.timezone.utc)


# --- a scripted HEC on loopback ---------------------------------------------------------
class FakeHec:
    def __init__(self):
        self.answers = []          # queue of (status, body) for POSTs; default 200 {"code":0};
                                   # status None = index the events, then drop the reply
        self.posts = []            # list of [event dicts] per accepted-or-not POST
        self.auth = []
        self.health = 200
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(outer.health)
                self.end_headers()
                self.wfile.write(b'{"text":"HEC is healthy","code":17}')

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(n).decode()
                outer.auth.append(self.headers.get("Authorization"))
                outer.posts.append([json.loads(ln) for ln in body.splitlines() if ln.strip()])
                status, text = outer.answers.pop(0) if outer.answers else (200, '{"text":"Success","code":0}')
                if status is None:              # Splunk indexed it, the reply never arrives
                    self.close_connection = True
                    return
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(text.encode())

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def events(self, sourcetype_prefix="azure:"):
        return [e for p in self.posts for e in p if e["sourcetype"].startswith(sourcetype_prefix)]


def la_row(item, ing, tg="2026-11-05T15:50:00.1234567Z", **cols):
    row = {"TimeGenerated": tg, "Type": "SigninLogs", "UserPrincipalName": "test-user-a@contosohealthlab.com",
           "ResultType": "50140", "IPAddress": "203.0.113.7", "LaIngestionTime": ing, "_ItemId": item}
    row.update(cols)
    return [json.dumps(row), item, ing]


def la_response(rows):
    return {"tables": [{"name": "PrimaryResult",
                        "columns": [{"name": "Row", "type": "dynamic"}, {"name": "ItemId", "type": "string"},
                                    {"name": "LaIngestionTime", "type": "datetime"}],
                        "rows": rows}]}


class FakeLA:
    """Returns the rows whose ingestion time is after the KQL's since-bound, like the
    real query, and records every KQL it was asked."""

    def __init__(self, rows):
        self.rows = rows
        self.kql = []

    def __call__(self, kql, timespan):
        self.kql.append(kql)
        since = kql.split("datetime(")[1].split(")")[0]
        keep = [r for r in self.rows if feed.tkey(r[2]) > feed.tkey(since)]
        keep.sort(key=lambda r: feed.tkey(r[2]))
        return la_response(keep)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_path = Path(self.tmp.name) / "state.json"
        self.hec_srv = FakeHec()
        self.hec = feed.Hec(self.hec_srv.url, TOKEN, sleep=lambda s: None)
        self.out = io.StringIO()
        self._redir = contextlib.redirect_stdout(self.out)
        self._redir.__enter__()

    def tearDown(self):
        self._redir.__exit__(None, None, None)
        self.hec_srv.close()
        self.tmp.cleanup()

    def state(self):
        return feed.State(self.state_path)


# --- time + KQL ---------------------------------------------------------------------------
class TimeAndKql(unittest.TestCase):
    def test_tkey_is_exact_across_fraction_lengths(self):
        self.assertLess(feed.tkey("2026-11-05T10:00:00.9Z"), feed.tkey("2026-11-05T10:00:00.95Z"))
        self.assertLess(feed.tkey("2026-11-05T10:00:00.1234567Z"), feed.tkey("2026-11-05T10:00:00.1234568Z"))
        self.assertEqual(feed.tkey("2026-11-05T10:00:00Z"), feed.tkey("2026-11-05T10:00:00.000Z"))
        with self.assertRaises(feed.FeedError):
            feed.tkey("2026-11-05 10:00:00")

    def test_epoch_is_millisecond_precision(self):
        self.assertEqual(feed.epoch("2026-11-05T00:00:01.2346789Z"), 1793836801.234)

    def test_iso_shift(self):
        self.assertEqual(feed.iso_shift("2026-11-05T10:05:00.1234567Z", -10), "2026-11-05T09:55:00.123456Z")

    def test_kql_refuses_unknown_table_and_bad_time(self):
        with self.assertRaises(feed.FeedError):
            feed.build_kql("SigninLogs | take 1", "2026-11-05T10:00:00Z")
        with self.assertRaises(feed.FeedError):
            feed.build_kql("SigninLogs", "now()")
        k = feed.build_kql("AuditLogs", "2026-11-05T10:00:00.5Z")
        self.assertIn("where LaIngestionTime > datetime(2026-11-05T10:00:00.5Z)", k)
        self.assertIn("ItemId = _ItemId", k)

    def test_timespan_covers_a_day_before_since(self):
        self.assertEqual(feed.timespan_for("2026-11-05T15:00:00Z", NOW), "PT26H")


# --- row transform ----------------------------------------------------------------------
class Transform(unittest.TestCase):
    def test_event_matches_replay_contract(self):
        row = {"TimeGenerated": "2026-11-05T15:50:00.1234567Z", "ZetaCol": "x", "_ItemId": "id-1",
               "LocationDetails": '{"countryOrRegion":"US"}', "UserDisplayName": "[EXT] Dana",
               "ResultType": "0", "Category": "SignInLogs"}
        ev = feed.to_event("AADNonInteractiveUserSignInLogs", row, "id-1", "loga-idlab")
        self.assertEqual(ev["sourcetype"], "azure:loganalytics:aadnoninteractiveusersigninlogs")
        self.assertEqual(ev["index"], "entra")
        self.assertEqual(ev["source"], "livefeed:loga-idlab:AADNonInteractiveUserSignInLogs")
        self.assertEqual(ev["time"], feed.epoch(row["TimeGenerated"]))
        self.assertEqual(ev["fields"], {"feed_item_id": "id-1"})
        self.assertEqual(ev["event"]["LocationDetails"], {"countryOrRegion": "US"})   # JSON text parsed
        self.assertEqual(ev["event"]["UserDisplayName"], "[EXT] Dana")                # kept verbatim
        self.assertNotIn("_ItemId", ev["event"])                                      # system column dropped
        keys = list(ev["event"])
        self.assertEqual(keys[0], "TimeGenerated")
        self.assertLess(keys.index("ResultType"), keys.index("ZetaCol"))

    def test_row_without_time_or_id_fails(self):
        with self.assertRaises(feed.FeedError):
            feed.to_event("SigninLogs", {"ResultType": "0"}, "id", "h")
        with self.assertRaises(feed.FeedError):
            feed.parse_rows(la_response([[json.dumps({"TimeGenerated": "2026-11-05T10:00:00Z"}), "", "2026-11-05T10:01:00Z"]]), "SigninLogs")
        bad = la_response([])
        bad["tables"][0]["columns"] = [{"name": "Row"}]
        with self.assertRaises(feed.FeedError):
            feed.parse_rows(bad, "SigninLogs")


# --- watermark + de-dup -------------------------------------------------------------------
class WatermarkAndDedup(Base):
    def test_first_run_starts_at_backfill_and_saves_watermark(self):
        la = FakeLA([la_row("a", "2026-11-05T15:51:00.1000001Z"), la_row("b", "2026-11-05T15:52:00.1000002Z")])
        sent, dups = feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW, backfill_h=24)
        self.assertEqual((sent, dups), (2, 0))
        self.assertIn("datetime(2026-11-04T16:00:00.000000Z)", la.kql[0])
        on_disk = json.loads(self.state_path.read_text())
        self.assertEqual(on_disk["tables"]["SigninLogs"]["hwm"], "2026-11-05T15:52:00.1000002Z")
        self.assertEqual(oct(self.state_path.stat().st_mode & 0o777), "0o600")

    def test_next_run_reads_from_watermark_minus_overlap_and_never_resends(self):
        rows = [la_row("a", "2026-11-05T15:51:00Z"), la_row("b", "2026-11-05T15:52:00Z")]
        la = FakeLA(rows)
        feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW)
        rows.append(la_row("c", "2026-11-05T15:58:00Z"))
        rows.append(la_row("late", "2026-11-05T15:51:30Z"))   # queryable late, inside the overlap
        sent, dups = feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW)
        self.assertIn("datetime(2026-11-05T15:42:00.000000Z)", la.kql[1])          # 15:52 - 10 min
        self.assertEqual((sent, dups), (2, 2))
        ids = [e["fields"]["feed_item_id"] for e in self.hec_srv.events()]
        self.assertEqual(sorted(ids), ["a", "b", "c", "late"])                       # each exactly once
        self.assertEqual(self.state().table("SigninLogs")["hwm"], "2026-11-05T15:58:00Z")
        # third run: nothing new at all (all four sit inside 15:58 - 10 min)
        self.assertEqual(feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW), (0, 4))
        self.assertEqual(len(self.hec_srv.events()), 4)

    def test_seen_ids_older_than_the_overlap_are_pruned(self):
        la = FakeLA([la_row("old", "2026-11-05T15:00:00Z"), la_row("new", "2026-11-05T15:58:00Z")])
        feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW)
        self.assertEqual(sorted(self.state().table("SigninLogs")["seen"]), ["new"])

    def test_dry_run_sends_nothing_and_keeps_state(self):
        la = FakeLA([la_row("a", "2026-11-05T15:51:00Z")])
        self.assertEqual(feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW, dry_run=True), (0, 0))
        self.assertEqual(self.hec_srv.posts, [])
        self.assertFalse(self.state_path.exists())

    def test_heartbeat_after_a_clean_run(self):
        la = FakeLA([la_row("a", "2026-11-05T15:51:00Z")])
        st = self.state()
        feed.run_once(st, la, self.hec, "loga-idlab", ["SigninLogs"], now=NOW)
        hb = [e for p in self.hec_srv.posts for e in p if e["sourcetype"] == "contoso:livefeed:heartbeat"]
        self.assertEqual(len(hb), 1)
        self.assertEqual(hb[0]["event"]["sent"], {"SigninLogs": 1})
        self.assertIn("last_success", json.loads(self.state_path.read_text()))


# --- HEC failures --------------------------------------------------------------------------
class HecFailures(Base):
    def test_rejected_batch_fails_and_watermark_covers_only_accepted_batches(self):
        la = FakeLA([la_row(str(i), "2026-11-05T15:5%d:00Z" % i) for i in range(4)])
        self.hec_srv.answers = [(200, '{"text":"Success","code":0}'), (400, '{"text":"Incorrect index","code":7}')]
        with self.assertRaises(feed.HecInDoubt) as cm:                     # a 4xx may have indexed part of it
            feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW, batch=2)
        self.assertIn("HTTP 400", str(cm.exception))
        self.assertIn("Incorrect index", str(cm.exception))
        self.assertEqual(len(self.hec_srv.posts), 2)                       # not retried
        ts = self.state().table("SigninLogs")
        self.assertEqual(ts["hwm"], "2026-11-05T15:51:00Z")               # batch 1 only
        self.assertEqual(sorted(ts["seen"]), ["0", "1"])
        self.assertEqual(sorted(ts["in_doubt"]), ["2", "3"])
        # next run: Splunk holds neither, so exactly those two are sent once
        feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW, batch=2, lookup=lambda ids: set())
        ids = [e["fields"]["feed_item_id"] for p in self.hec_srv.posts[:1] + self.hec_srv.posts[2:] for e in p]
        self.assertEqual(sorted(ids), ["0", "1", "2", "3"])
        self.assertEqual(self.state().table("SigninLogs")["in_doubt"], {})

    def test_accepted_batch_whose_reply_is_lost_is_never_sent_twice(self):
        la = FakeLA([la_row("a", "2026-11-05T15:51:00Z"), la_row("b", "2026-11-05T15:52:00Z")])
        self.hec_srv.answers = [(None, "")]
        with self.assertRaises(feed.HecInDoubt):
            feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW)
        self.assertEqual(len(self.hec_srv.posts), 1)                       # no blind retry
        self.assertIsNone(self.state().table("SigninLogs")["hwm"])
        asked = []

        def splunk_has(ids):
            asked.append(list(ids))
            return {"a", "b"}
        self.assertEqual(feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW, lookup=splunk_has), (0, 2))
        self.assertEqual(asked, [["a", "b"]])
        self.assertEqual(sorted(e["fields"]["feed_item_id"] for e in self.hec_srv.events()), ["a", "b"])   # one copy each

    def test_in_doubt_rows_splunk_lacks_are_sent_once(self):
        la = FakeLA([la_row("a", "2026-11-05T15:51:00Z"), la_row("b", "2026-11-05T15:52:00Z")])
        self.hec_srv.answers = [(None, "")]
        with self.assertRaises(feed.HecInDoubt):
            feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW)
        self.assertEqual(feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW, lookup=lambda ids: {"a"}), (1, 1))
        # first POST indexed a+b (reply lost); Splunk holds only "a" (a 4xx part-way would look like this)
        self.assertEqual(sorted(e["fields"]["feed_item_id"] for e in self.hec_srv.posts[1]), ["b"])

    def test_in_doubt_without_an_answer_from_splunk_sends_nothing(self):
        la = FakeLA([la_row("a", "2026-11-05T15:51:00Z")])
        self.hec_srv.answers = [(None, "")]
        with self.assertRaises(feed.HecInDoubt):
            feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW)

        def down(ids):
            raise feed.FeedError("Splunk management API unreachable")
        for lk in (None, down):
            with self.assertRaises(feed.FeedError):
                feed.feed_table("SigninLogs", self.state(), la, self.hec, "loga-idlab", NOW, lookup=lk)
        self.assertEqual(len(self.hec_srv.posts), 1)
        self.assertEqual(sorted(self.state().table("SigninLogs")["in_doubt"]), ["a"])

    def test_partial_log_analytics_result_is_refused_whole(self):
        resp = la_response([la_row("a", "2026-11-05T15:51:00Z")])
        resp["error"] = {"code": "PartialError", "message": "There were some errors when processing your query."}
        with self.assertRaises(feed.FeedError) as cm:
            feed.feed_table("SigninLogs", self.state(), lambda k, t: resp, self.hec, "loga-idlab", NOW)
        self.assertIn("partial result", str(cm.exception))
        self.assertEqual(self.hec_srv.posts, [])
        self.assertFalse(self.state_path.exists())

    def test_200_without_code_zero_is_a_failure(self):
        self.hec_srv.answers = [(200, '{"text":"Invalid data format","code":6}')]
        with self.assertRaises(feed.FeedError):
            self.hec.post([{"event": {}}])

    def test_503_is_retried_then_succeeds(self):
        self.hec_srv.answers = [(503, '{"text":"Server is busy","code":9}'), (200, '{"text":"Success","code":0}')]
        self.hec.post([{"event": {}}])
        self.assertEqual(len(self.hec_srv.posts), 2)

    def test_refused_connection_is_retried_then_fails_but_is_not_in_doubt(self):
        sleeps = []
        dead = feed.Hec("http://127.0.0.1:9", TOKEN, sleep=sleeps.append)
        with self.assertRaises(feed.FeedError) as cm:
            dead.post([{"event": {}}])
        self.assertNotIsInstance(cm.exception, feed.HecInDoubt)            # nothing can have been indexed
        self.assertIn("connection refused", str(cm.exception))
        self.assertEqual(sleeps, [5, 10])

    def test_failed_table_means_no_heartbeat_and_exit_path(self):
        good = FakeLA([la_row("a", "2026-11-05T15:51:00Z")])

        def query(kql, ts):
            if kql.startswith("AuditLogs"):
                raise feed.FeedError("Log Analytics query failed: HTTP 403")
            return good(kql, ts)
        with self.assertRaises(feed.FeedError) as cm:
            feed.run_once(self.state(), query, self.hec, "loga-idlab", ["SigninLogs", "AuditLogs"], now=NOW)
        self.assertIn("1 of 2 tables failed", str(cm.exception))
        self.assertEqual([e for p in self.hec_srv.posts for e in p if e["sourcetype"].startswith("contoso:")], [])
        self.assertEqual(len(self.hec_srv.events()), 1)                    # the good table still went

    def test_unhealthy_hec_stops_before_querying(self):
        self.hec_srv.health = 503
        la = FakeLA([la_row("a", "2026-11-05T15:51:00Z")])
        with self.assertRaises(feed.FeedError):
            feed.run_once(self.state(), la, self.hec, "loga-idlab", ["SigninLogs"], now=NOW)
        self.assertEqual(la.kql, [])

    def test_token_is_sent_as_header_but_never_printed_or_raised(self):
        self.hec_srv.answers = [(401, '{"text":"Invalid token","code":4}')]
        la = FakeLA([la_row("a", "2026-11-05T15:51:00Z")])
        try:
            feed.run_once(self.state(), la, self.hec, "loga-idlab", ["SigninLogs"], now=NOW)
        except feed.FeedError as e:
            self.assertNotIn(TOKEN, str(e))
        self.assertEqual(self.hec_srv.auth[0], "Splunk " + TOKEN)
        self.assertNotIn(TOKEN, self.out.getvalue())
        self.assertNotIn(TOKEN, self.state_path.read_text() if self.state_path.exists() else "")

    def test_non_loopback_splunk_is_refused(self):
        with self.assertRaises(feed.FeedError):
            feed.Hec("https://splunk.example.com:8088", TOKEN)


# --- state, lock, Keychain ------------------------------------------------------------------
class StateLockKeychain(Base):
    def test_corrupt_state_stops_the_run(self):
        self.state_path.write_text("{not json")
        with self.assertRaises(feed.FeedError):
            feed.State(self.state_path)

    def test_second_copy_refuses_while_the_lock_is_held(self):
        lock = open(os.path.join(self.tmp.name, "lock"), "w")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with mock.patch.object(feed, "keychain_get") as kc:
                self.assertEqual(feed.main(["--state-dir", self.tmp.name, "run", "--op", "/bin/true"]), 3)
                kc.assert_not_called()
        finally:
            lock.close()

    def test_keychain_not_found_vs_could_not_read(self):
        with mock.patch.object(feed.subprocess, "run", return_value=subprocess.CompletedProcess([], 44, "", "")):
            self.assertIsNone(feed.keychain_get("svc", "acct"))
        with mock.patch.object(feed.subprocess, "run", return_value=subprocess.CompletedProcess([], 51, "", "")):
            with self.assertRaises(feed.FeedError):
                feed.keychain_get("svc", "acct")

    def test_keychain_write_goes_over_stdin_never_argv(self):
        calls = []

        def fake_run(args, **kw):
            calls.append((args, kw.get("input")))
            if args[:2] == ["security", "find-generic-password"]:
                return subprocess.CompletedProcess(args, 0, TOKEN + "\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        with mock.patch.object(feed.subprocess, "run", side_effect=fake_run):
            feed.keychain_set("contoso-splunk-hec-live", "contoso_live_feed", "label", TOKEN)
        self.assertEqual(calls[0][0], ["security", "-i"])
        self.assertIn(TOKEN, calls[0][1])
        self.assertTrue(all(TOKEN not in " ".join(a) for a, _ in calls))
        with self.assertRaises(feed.FeedError):
            feed.keychain_set("s", "a", "l", "has space; rm -rf")

    def test_missing_hec_token_stops_run(self):
        with mock.patch.object(feed, "keychain_get", return_value=None):
            self.assertEqual(feed.main(["--state-dir", self.tmp.name, "run", "--op", "/bin/true"]), 1)
        self.assertIn("run setup first", self.out.getvalue())


# --- LaunchAgent + preflight verdict -----------------------------------------------------
class AgentAndCheck(unittest.TestCase):
    VALUES = {"LABEL": "com.contoso.splunk-live-feed", "PYTHON": "/usr/bin/python3", "SCRIPT": "/x/feed.py",
              "OP": "/x/op", "STATE_DIR": "/x/state", "LOG": "/x/feed.log", "PATH": "/usr/bin:/bin"}

    def test_template_renders_a_valid_agent_every_300_seconds(self):
        pl = plistlib.loads(feed.render_plist(feed.PLIST_TEMPLATE.read_text(), self.VALUES))
        self.assertEqual(pl["Label"], "com.contoso.splunk-live-feed")
        self.assertEqual(pl["StartInterval"], 300)
        self.assertTrue(pl["RunAtLoad"])
        self.assertEqual(pl["ProgramArguments"][:3], ["/usr/bin/python3", "-I", "/x/feed.py"])
        self.assertIn("run", pl["ProgramArguments"])
        self.assertIsNone(re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                                    feed.PLIST_TEMPLATE.read_text()))                         # no token value
        self.assertNotIn("TOKEN", feed.PLIST_TEMPLATE.read_text())                                 # no token placeholder

    def test_unfilled_placeholder_is_refused(self):
        v = dict(self.VALUES)
        del v["OP"]
        with self.assertRaises(feed.FeedError):
            feed.render_plist(feed.PLIST_TEMPLATE.read_text(), v)

    def test_check_verdict(self):
        now = 1_800_000_000.0
        ok, msg = feed.evaluate_check(now, now - 4 * 60, now - 6 * 60, 120, 15)
        self.assertTrue(ok)
        self.assertIn("last poll 4 min ago", msg)
        self.assertFalse(feed.evaluate_check(now, now - 15 * 60, now - 60, 120, 15)[0])   # 15 min = stale
        ok, msg = feed.evaluate_check(now, None, None, 0, 15)
        self.assertFalse(ok)
        self.assertIn("no feed event in Splunk", msg)


# --- setup: HEC token + search-only user over a fake Splunk REST API -------------------------
class FakeSplunkRest:
    """Just enough of Splunk's management API (data/inputs/http, authorization/roles,
    authentication/users, current-context) to drive setup. Records every POST body."""

    TOKEN_PATH = "/servicesNS/nobody/splunk_httpinput/data/inputs/http"
    TOKEN_ITEM = TOKEN_PATH + "/http%3A%2F%2Fcontoso_live_feed"

    def __init__(self):
        self.token = None            # dict(index, indexes, token) once created
        self.ignore_updates = False
        self.roles, self.users, self.posts, self.role_posts = {}, {}, [], []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj=None):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(obj or {}).encode())

            def _user(self):
                import base64
                u, _, pw = base64.b64decode(self.headers["Authorization"].split()[1]).decode().partition(":")
                return u, pw

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == outer.TOKEN_ITEM:
                    return self._send(200, {"entry": [{"content": outer.token}]}) if outer.token else self._send(404)
                if path.startswith("/services/authorization/roles/"):
                    name = path.rsplit("/", 1)[1]
                    return self._send(200, {"entry": [{"content": outer.roles[name]}]}) if name in outer.roles else self._send(404)
                if path.startswith("/services/authentication/users/"):
                    return self._send(200, {"entry": [{}]}) if path.rsplit("/", 1)[1] in outer.users else self._send(404)
                if path == "/services/authentication/current-context":
                    u, pw = self._user()
                    if u in outer.users and outer.users[u]["password"] == pw:
                        return self._send(200, {"entry": [{"content": {"roles": outer.users[u]["roles"]}}]})
                    return self._send(401)
                self._send(404)

            def do_POST(self):
                path = self.path.split("?")[0]
                body = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()))
                outer.posts.append((path, body))
                if path == outer.TOKEN_PATH:
                    outer.token = {"index": body["index"], "indexes": [body["indexes"]], "token": TOKEN, "disabled": False}
                    return self._send(201, {"entry": [{"content": outer.token}]})
                if path == outer.TOKEN_ITEM:
                    if not outer.ignore_updates:
                        outer.token.update(index=body["index"], indexes=[body["indexes"]], disabled=False)
                    return self._send(200, {"entry": [{"content": outer.token}]})
                if path.startswith("/services/authorization/roles"):
                    name = body.get("name") or path.rsplit("/", 1)[1]
                    cur = outer.roles.setdefault(name, {"imported_roles": []})
                    cur["capabilities"] = [body["capabilities"]]          # Splunk sets, it does not append
                    cur["srchIndexesAllowed"] = [body["srchIndexesAllowed"]]
                    cur["srchIndexesDefault"] = [body["srchIndexesDefault"]]
                    outer.role_posts.append(body)
                    return self._send(201)
                if path.startswith("/services/authentication/users"):
                    name = body.get("name") or path.rsplit("/", 1)[1]
                    outer.users[name] = {"password": body["password"], "roles": [body["roles"]]}
                    return self._send(201)
                self._send(404)

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Setup(unittest.TestCase):
    def setUp(self):
        self.rest = FakeSplunkRest()
        self.kc = {}
        self.patches = [mock.patch.object(feed, "MGMT_URL", self.rest.url),
                        mock.patch.object(feed, "keychain_get", side_effect=lambda s, a: self.kc.get(s)),
                        mock.patch.object(feed, "keychain_set", side_effect=lambda s, a, label, v: self.kc.__setitem__(s, v))]
        for p in self.patches:
            p.start()
        self.admin = feed.SplunkRest("admin", "admin-password-not-real")
        self._out = contextlib.redirect_stdout(io.StringIO())
        self._out.__enter__()

    def tearDown(self):
        self._out.__exit__(None, None, None)
        for p in self.patches:
            p.stop()
        self.rest.close()

    def test_creates_the_feed_token_pinned_to_entra_and_keeps_it_in_keychain(self):
        self.assertEqual(feed.hec_token_setup(self.admin), TOKEN)
        path, body = self.rest.posts[0]
        self.assertEqual(path, FakeSplunkRest.TOKEN_PATH)
        self.assertEqual((body["name"], body["index"], body["indexes"]), ("contoso_live_feed", "entra", "entra"))
        self.assertEqual(self.kc["contoso-splunk-hec-live"], TOKEN)

    def test_repins_an_existing_token_that_could_write_elsewhere(self):
        self.rest.token = {"index": "main", "indexes": [], "token": TOKEN, "disabled": False}
        feed.hec_token_setup(self.admin)
        self.assertEqual(self.rest.posts[-1][0], FakeSplunkRest.TOKEN_ITEM)
        self.assertEqual(self.rest.token["indexes"], ["entra"])

    def test_refuses_when_the_pin_does_not_read_back(self):
        self.rest.token = {"index": "main", "indexes": ["main"], "token": TOKEN, "disabled": False}
        self.rest.ignore_updates = True
        with self.assertRaises(feed.FeedError):
            feed.hec_token_setup(self.admin)
        self.assertNotIn("contoso-splunk-hec-live", self.kc)

    def test_reader_gets_only_search_on_entra(self):
        feed.reader_setup(self.admin)
        sent = self.rest.role_posts[0]
        self.assertEqual((sent["capabilities"], sent["srchIndexesAllowed"], sent["srchIndexesDefault"]), ("search", "entra", "entra"))
        self.assertNotIn("imported_roles", sent)
        self.assertEqual(self.rest.users["contoso-feed-check"]["roles"], ["contoso_feed_reader"])
        self.assertEqual(self.rest.users["contoso-feed-check"]["password"], self.kc["contoso-splunk-feed-reader"])

    def test_a_working_reader_password_is_kept(self):
        self.rest.roles["contoso_feed_reader"] = {"imported_roles": []}
        self.rest.users["contoso-feed-check"] = {"password": "kept-password-0123456789", "roles": ["contoso_feed_reader"]}
        self.kc["contoso-splunk-feed-reader"] = "kept-password-0123456789"
        feed.reader_setup(self.admin)
        self.assertFalse([p for p, _ in self.rest.posts if p.startswith("/services/authentication/users")])

    def test_a_reader_with_extra_roles_is_refused(self):
        self.rest.roles["contoso_feed_reader"] = {"imported_roles": []}
        self.rest.users["contoso-feed-check"] = {"password": "kept-password-0123456789", "roles": ["contoso_feed_reader"]}
        self.kc["contoso-splunk-feed-reader"] = "kept-password-0123456789"
        self.rest.users["contoso-feed-check"]["roles"] = ["contoso_feed_reader", "admin"]
        with self.assertRaises(feed.FeedError):
            feed.reader_setup(self.admin)


    def test_a_role_that_imports_another_role_is_refused(self):
        self.rest.roles["contoso_feed_reader"] = {"imported_roles": ["user"]}
        with self.assertRaises(feed.FeedError) as cm:
            feed.reader_setup(self.admin)
        self.assertIn("broader", str(cm.exception))
        self.assertNotIn("contoso-splunk-feed-reader", self.kc)


if __name__ == "__main__":
    unittest.main()
