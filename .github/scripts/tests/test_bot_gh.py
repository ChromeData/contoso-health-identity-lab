"""Tests for lab/scripts/operator/github-bot/bot-gh (karen-review A1).

bot-gh lets AI coding agents act on GitHub as the lab's GitHub App (the bot),
so the PR author differs from the owner who approves the apply. These tests
run it against stub `security`, `curl`, `gh` and `git` on PATH (no network,
no Keychain) and pin what matters:

  * the App JWT is RS256-signed with the Keychain key and verifies,
  * the installation token is scoped to this one repository,
  * gh gets the token only in GH_TOKEN; git only through $BOT_TOKEN,
  * the key, the JWT and the token never appear in any argv or on stdout,
  * commits are authored by "<slug>[bot]" with its noreply e-mail,
  * the credential helper answers only https://github.com (never another
    host), and an SSH remote is refused (it would push with the owner's
    SSH key). These two run the REAL git with an isolated config.

    python3 -m unittest discover -s .github/scripts/tests -p 'test_*.py' -v
"""

import base64
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
BOT_GH = os.path.join(ROOT, "lab", "scripts", "operator", "github-bot", "bot-gh")
TOKEN = "ghs_STUBTOKEN0123456789"
REAL_GIT = shutil.which("git")
STUB_SSH = r"""#!/usr/bin/env bash
echo "ssh $*" >> "$STUB_DIR/ssh.log"
exit 1
"""

STUB_SECURITY = r"""#!/usr/bin/env bash
echo "security $*" >> "$STUB_DIR/argv.log"
[ "$1" = find-generic-password ] && [ "$3" = contoso-lab-bot-key ] || exit 44
cat "$STUB_DIR/key.b64"
"""

# curl reads its whole config (auth header, url, method, body) from stdin.
STUB_CURL = r"""#!/usr/bin/env python3
import json, os, re, subprocess, sys, base64
d = os.environ["STUB_DIR"]
open(os.path.join(d, "argv.log"), "a").write("curl " + " ".join(sys.argv[1:]) + "\n")
cfg = sys.stdin.read()
open(os.path.join(d, "curl-config.log"), "a").write(cfg + "\n---\n")
url = re.search(r'^url = "(.*)"$', cfg, re.M).group(1)
jwt = re.search(r'Authorization: Bearer ([^"]+)"', cfg).group(1)
h, p, s = jwt.split(".")
pad = lambda x: x + "=" * (-len(x) % 4)
sig = base64.urlsafe_b64decode(pad(s))
open(os.path.join(d, "sig.bin"), "wb").write(sig)
open(os.path.join(d, "signed.txt"), "w").write(h + "." + p)
ok = subprocess.run(["openssl", "dgst", "-sha256", "-verify", os.path.join(d, "pub.pem"),
                     "-signature", os.path.join(d, "sig.bin"), os.path.join(d, "signed.txt")],
                    capture_output=True).returncode == 0
if not ok:
    print('{"message":"bad JWT"}'); sys.exit(22)
claims = json.loads(base64.urlsafe_b64decode(pad(p)))
open(os.path.join(d, "claims.json"), "w").write(json.dumps(claims))
if url.endswith("/repos/ChromeData/contoso-health-identity-lab/installation"):
    print('{"id": 4242}')
elif url.endswith("/app/installations/4242/access_tokens"):
    body = re.search(r'^data = "(.*)"$', cfg, re.M).group(1).replace('\\"', '"')
    open(os.path.join(d, "token-body.json"), "w").write(body)
    print(json.dumps({"token": os.environ["STUB_TOKEN"]}))
else:
    print('{"message":"Not Found"}'); sys.exit(22)
"""

STUB_RECORD = r"""#!/usr/bin/env bash
echo "@@NAME@@ $*" >> "$STUB_DIR/argv.log"
{
  echo "GH_TOKEN=${GH_TOKEN:-}"
  echo "BOT_TOKEN=${BOT_TOKEN:-}"
  echo "AUTHOR=${GIT_AUTHOR_NAME:-} <${GIT_AUTHOR_EMAIL:-}>"
} > "$STUB_DIR/@@NAME@@-env.log"
echo "@@NAME@@ ran"
"""


class BotGhTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.d = self.tmp.name
        self.bin = os.path.join(d, "bin")
        self.home = os.path.join(d, "home")
        os.makedirs(self.bin)
        os.makedirs(self.home)
        key = os.path.join(d, "key.pem")
        subprocess.run(["openssl", "genrsa", "-out", key, "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", key, "-pubout", "-out", os.path.join(d, "pub.pem")],
                       check=True, capture_output=True)
        self.pem = open(key).read()
        open(os.path.join(d, "key.b64"), "w").write(base64.b64encode(self.pem.encode()).decode())
        os.remove(key)
        stubs = {
            "security": STUB_SECURITY,
            "curl": STUB_CURL,
            "gh": STUB_RECORD.replace("@@NAME@@", "gh"),
            "git": STUB_RECORD.replace("@@NAME@@", "git"),
        }
        for name, body in stubs.items():
            p = os.path.join(self.bin, name)
            open(p, "w").write(body)
            os.chmod(p, 0o755)
        open(os.path.join(self.home, "bot.env"), "w").write(textwrap.dedent("""\
            BOT_APP_ID=123456
            BOT_SLUG=contoso-health-lab-bot
            BOT_USER_ID=987654
            BOT_REPO=ChromeData/contoso-health-identity-lab
            """))

    def tearDown(self):
        self.tmp.cleanup()

    def run_bot(self, *args, real_git=False, stdin=None, cwd=None):
        env = dict(os.environ)
        env.update(PATH=self.bin + os.pathsep + env["PATH"], STUB_DIR=self.d,
                   STUB_TOKEN=TOKEN, CONTOSO_OPERATOR_HOME=self.home)
        env.pop("GH_TOKEN", None)
        if real_git:
            # The real git first on PATH (not the recording stub), with no
            # owner config at all, and an `ssh` stub that records any call.
            real = os.path.join(self.d, "realbin")
            os.makedirs(real, exist_ok=True)
            if not os.path.exists(os.path.join(real, "git")):
                os.symlink(REAL_GIT, os.path.join(real, "git"))
                p = os.path.join(real, "ssh")
                open(p, "w").write(STUB_SSH)
                os.chmod(p, 0o755)
            env["PATH"] = real + os.pathsep + env["PATH"]
            env.update(HOME=self.home, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
            for k in ("GIT_ASKPASS", "SSH_ASKPASS", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_ALLOW_PROTOCOL"):
                env.pop(k, None)
        return subprocess.run(["bash", BOT_GH, *args], env=env, capture_output=True, text=True,
                              input=stdin, cwd=cwd)

    def read(self, name):
        p = os.path.join(self.d, name)
        return open(p).read() if os.path.exists(p) else ""

    def assert_no_secret_leak(self, r):
        argv = self.read("argv.log")
        jwt = self.read("signed.txt")
        for secret in (TOKEN, self.read("key.b64"), "BEGIN", jwt):
            if secret:
                self.assertNotIn(secret, argv, "a secret reached a command line")
                self.assertNotIn(secret, r.stdout + r.stderr, "a secret was printed")

    def test_gh_runs_as_bot_with_token_in_env_only(self):
        r = self.run_bot("gh", "pr", "create", "--title", "x")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("gh pr create --title x", self.read("argv.log"))
        self.assertIn("GH_TOKEN=" + TOKEN, self.read("gh-env.log"))
        self.assert_no_secret_leak(r)

    def test_jwt_claims_and_repo_scoped_token(self):
        r = self.run_bot("gh", "api", "user")
        self.assertEqual(r.returncode, 0, r.stderr)
        claims = json.loads(self.read("claims.json"))
        self.assertEqual(claims["iss"], "123456")
        self.assertLessEqual(claims["exp"] - claims["iat"], 600)  # GitHub's 10-minute cap
        self.assertEqual(json.loads(self.read("token-body.json")),
                         {"repositories": ["contoso-health-identity-lab"]})

    def test_git_commit_authored_by_bot_token_via_helper(self):
        r = self.run_bot("git", "commit", "-m", "msg")
        self.assertEqual(r.returncode, 0, r.stderr)
        env = self.read("git-env.log")
        self.assertIn("BOT_TOKEN=" + TOKEN, env)
        self.assertIn("AUTHOR=contoso-health-lab-bot[bot] <987654+contoso-health-lab-bot[bot]@users.noreply.github.com>", env)
        self.assertIn("credential.helper=", self.read("argv.log"))
        self.assert_no_secret_leak(r)

    def test_push_uses_https_and_refuses_without_branch(self):
        r = self.run_bot("push", "feat/x")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("push https://github.com/ChromeData/contoso-health-identity-lab.git HEAD:refs/heads/feat/x",
                      self.read("argv.log"))
        self.assert_no_secret_leak(r)
        self.assertNotEqual(self.run_bot("push").returncode, 0)

    @unittest.skipUnless(REAL_GIT, "needs git")
    def test_credential_helper_answers_github_https_only(self):
        # Another host (the Greptile finding on PR #241): no password at all.
        for req in ("protocol=https\nhost=example.invalid\n\n",
                    "protocol=http\nhost=github.com\n\n",
                    "protocol=https\nhost=github.com.example.invalid\n\n"):
            r = self.run_bot("git", "credential", "fill", real_git=True, stdin=req)
            self.assertNotIn(TOKEN, r.stdout + r.stderr, "token given for: " + req.split()[1])
            self.assertNotEqual(r.returncode, 0, "git found a credential for " + req.split()[1])
        # github.com over https: the bot's token (a stub token, test only).
        r = self.run_bot("git", "credential", "fill", real_git=True,
                         stdin="protocol=https\nhost=github.com\npath=ChromeData/x.git\n\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("username=x-access-token", r.stdout)
        self.assertIn("password=" + TOKEN, r.stdout)
        self.assertNotIn(TOKEN, self.read("argv.log"))

    @unittest.skipUnless(REAL_GIT, "needs git")
    def test_ssh_remote_is_refused_never_owner_key(self):
        repo = os.path.join(self.d, "repo")
        subprocess.run([REAL_GIT, "init", "-q", repo], check=True)
        # A commit, so the push gets as far as connecting to the remote.
        subprocess.run([REAL_GIT, "-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "commit", "-q", "--allow-empty", "-m", "x"], check=True)
        for url in ("git@github.com:ChromeData/contoso-health-identity-lab.git",
                    "ssh://git@github.com/ChromeData/contoso-health-identity-lab.git"):
            r = self.run_bot("git", "push", url, "HEAD:refs/heads/x", real_git=True, cwd=repo)
            self.assertNotEqual(r.returncode, 0, "an SSH push did not fail")
            self.assertEqual(self.read("ssh.log"), "", "ssh ran: the push would use the owner's SSH key")
        # Nor through the owner's own pushInsteadOf rewrite of the HTTPS URL.
        subprocess.run([REAL_GIT, "-C", repo, "config", "url.git@github.com:.pushInsteadOf",
                        "https://github.com/"], check=True)
        r = self.run_bot("push", "feat/x", real_git=True, cwd=repo)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.read("ssh.log"), "", "ssh ran after a pushInsteadOf rewrite")

    def test_missing_key_fails_closed(self):
        os.remove(os.path.join(self.d, "key.b64"))
        r = self.run_bot("gh", "pr", "list")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("gh pr list", self.read("argv.log"), "gh ran without a bot token")

    def test_missing_config_fails_closed(self):
        os.remove(os.path.join(self.home, "bot.env"))
        r = self.run_bot("gh", "pr", "list")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("new-bot-app.sh", r.stderr)


if __name__ == "__main__":
    unittest.main()
