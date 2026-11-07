#!/usr/bin/env bash
# =============================================================================
# new-bot-app.sh - the OWNER makes the lab's GitHub App (the bot) once
# -----------------------------------------------------------------------------
# Why (karen-review A1): a GitHub App gives the AI coding agents their own
# GitHub identity, "<slug>[bot]". It is free on every plan and needs no extra
# seat. Then the PR author and merger (the bot) differ from the approver (the
# owner, ChromeData), and the apply gate can check that by login.
#
# Run it yourself, signed in to github.com as ChromeData in your default
# browser. An AI assistant must not run it: creating the App is the owner's
# decision, and GitHub asks for a click on github.com.
#
#   lab/scripts/operator/github-bot/new-bot-app.sh [app-name]
#
# What it does (GitHub "App manifest" flow):
#   1. writes a one-page form with the App manifest below and opens it; the
#      page posts the manifest to github.com/settings/apps/new,
#   2. you check the name and click "Create GitHub App" on github.com,
#   3. GitHub sends your browser back to http://127.0.0.1:$PORT/callback with
#      a one-time code (valid 1 hour); a local listener takes it and checks
#      the random state value,
#   4. the code is exchanged for the App's private key (curl reads the URL from
#      stdin, so the code is never in argv); the key goes straight into the
#      login Keychain item contoso-lab-bot-key through `security -i` on stdin.
#      The client secret and webhook secret are not needed and are dropped.
#   5. ids only (no secret) go to ~/.contoso-operator/bot.env.
# Then you install the App on this ONE repository (the script prints the link).
#
# Permissions (least privilege for "push, open PRs, merge"):
#   contents write, pull_requests write, workflows write (agents edit
#   .github/workflows), actions read, checks read, issues READ (the bot cannot
#   comment on an "Approve: apply" issue), metadata read. No webhook.
# =============================================================================
set -euo pipefail

NAME="${1:-contoso-health-lab-bot}"
REPO="${BOT_REPO:-ChromeData/contoso-health-identity-lab}"
PORT="${BOT_CALLBACK_PORT:-8765}"
BOT_HOME="${CONTOSO_OPERATOR_HOME:-$HOME/.contoso-operator}"
SERVICE="contoso-lab-bot-key"

umask 077
mkdir -p "$BOT_HOME"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
state="$(openssl rand -hex 16)"

python3 -I - "$NAME" "$REPO" "$PORT" "$state" > "$tmp/form.html" <<'PY'
import html, json, sys
name, repo, port, state = sys.argv[1:]
manifest = {
    "name": name,
    "url": f"https://github.com/{repo}",
    "description": "Contoso Health lab: AI coding agents push, open PRs and merge as this bot. Only the owner approves applies.",
    "public": False,
    "redirect_url": f"http://127.0.0.1:{port}/callback",
    "hook_attributes": {"url": "https://example.invalid/no-webhook", "active": False},
    "default_events": [],
    "default_permissions": {
        "contents": "write",
        "pull_requests": "write",
        "workflows": "write",
        "actions": "read",
        "checks": "read",
        "issues": "read",
        "metadata": "read",
    },
}
print(f"""<!doctype html><meta charset="utf-8"><title>Create {html.escape(name)}</title>
<body onload="document.forms[0].submit()">
<form method="post" action="https://github.com/settings/apps/new?state={state}">
<input type="hidden" name="manifest" value="{html.escape(json.dumps(manifest))}">
<button>Continue to GitHub</button></form>""")
PY

echo "Opening GitHub. Check the App name, then click \"Create GitHub App\"."
open "$tmp/form.html"

# One-shot listener: takes the code, checks state, answers the browser.
code="$(python3 -I - "$PORT" "$state" <<'PY'
import sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
port, want = int(sys.argv[1]), sys.argv[2]
got = {}
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        ok = q.get("state", [""])[0] == want and q.get("code")
        if ok:
            got["code"] = q["code"][0]
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Done. Go back to the terminal." if ok else b"State mismatch. Nothing was saved.")
    def log_message(self, *a):
        pass
srv = HTTPServer(("127.0.0.1", port), H)
srv.timeout = 600
while "code" not in got:
    srv.handle_request()
print(got["code"])
PY
)"

# Exchange the code. The response holds the private key: it goes from curl
# into python on a pipe, and python hands it to `security -i` on stdin.
# (The python is written to a file first, because stdin carries the response.)
cat > "$tmp/save.py" <<'PY'
import base64, json, subprocess, sys, urllib.request
service, env_path, repo = sys.argv[1:]
app = json.load(sys.stdin)
b64 = base64.b64encode(app["pem"].encode()).decode()
cmd = f'add-generic-password -U -s {service} -a bot -l "Contoso lab GitHub App private key (base64 PEM)" -w {b64}\n'
subprocess.run(["security", "-i"], input=cmd.encode(), check=True, stdout=subprocess.DEVNULL)
slug = app["slug"]
with urllib.request.urlopen(f"https://api.github.com/users/{slug}%5Bbot%5D") as r:
    user_id = json.load(r)["id"]
with open(env_path, "w") as f:
    f.write(f"# Lab GitHub App (ids only, no secret). Written by new-bot-app.sh\n"
            f"BOT_APP_ID={app['id']}\nBOT_SLUG={slug}\nBOT_USER_ID={user_id}\nBOT_REPO={repo}\n")
print(f"Created App {slug} (id {app['id']}). Bot login: {slug}[bot]. Key stored in Keychain item {service}.")
print(f"Next: install it on {repo} only: https://github.com/apps/{slug}/installations/new")
PY
printf 'url = "https://api.github.com/app-manifests/%s/conversions"\nrequest = "POST"\nheader = "Accept: application/vnd.github+json"\n' "$code" \
  | curl -sS --fail-with-body -K - \
  | python3 -I "$tmp/save.py" "$SERVICE" "$BOT_HOME/bot.env" "$REPO"
unset code
echo "Then check: lab/scripts/operator/github-bot/bot-gh gh api repos/$REPO --jq .full_name"
