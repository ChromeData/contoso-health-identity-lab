#!/usr/bin/env bash
# =============================================================================
# obs-setup.sh - one-time OBS Studio setup for the recording cockpit.
#
# Turns on OBS's built-in remote control (obs-websocket v5, 127.0.0.1:4455) so
# the cockpit can start / pause / resume / stop the recording itself, and skips
# OBS's first-run wizard. The websocket password is generated once and kept in
# the macOS login Keychain (service contoso-lab-obs-ws). It goes into
# Keychain through stdin (security -i), never through argv. OBS itself needs
# the password in its own settings file, so that file is written chmod 600 by
# a node one-liner that reads the Keychain inside its own process.
#
# Safe to re-run: keeps an existing password, only rewrites the two files.
# OBS must be QUIT while this runs (it rewrites its settings on exit).
# The scene ("Contoso demo": the recording display + the microphone) is made
# by the cockpit over the websocket at start-up, not here.
# =============================================================================
set -euo pipefail
SVC=contoso-lab-obs-ws
DIR="$HOME/Library/Application Support/obs-studio"

if pgrep -x OBS >/dev/null; then echo "Quit OBS first (it rewrites its settings when it closes)."; exit 1; fi

if ! security find-generic-password -s "$SVC" >/dev/null 2>&1; then
  pw="$(openssl rand -hex 20)"
  printf 'add-generic-password -U -s %s -a obs-websocket -l "OBS websocket (contoso cockpit)" -w %s\n' "$SVC" "$pw" | security -i >/dev/null
  unset pw
  echo "Made a new OBS websocket password (Keychain: $SVC)"
else
  echo "Keeping the OBS websocket password already in Keychain ($SVC)"
fi

mkdir -p "$DIR/plugin_config/obs-websocket"
# The password is read inside node, never echoed or put in argv.
node -e '
const { execFileSync } = require("child_process"); const fs = require("fs");
const pw = execFileSync("security", ["find-generic-password", "-s", process.argv[1], "-w"], { encoding: "utf8" }).trim();
const f = process.argv[2];
const cfg = { alerts_enabled: false, auth_required: true, first_load: false, server_enabled: true, server_password: pw, server_port: 4455 };
fs.writeFileSync(f, JSON.stringify(cfg, null, 2), { mode: 0o600 }); fs.chmodSync(f, 0o600);
' "$SVC" "$DIR/plugin_config/obs-websocket/config.json"
echo "obs-websocket: on, 127.0.0.1:4455, password required"

# FirstRun=true means "the first run already happened": no auto-config wizard.
# MacOSPermissionsDialogLastShown=1: OBS's own "Review App Permissions" window
# is modal and blocked remote StartRecord here; macOS's permission is granted
# in System Settings instead (see the README). ConfirmOnExit=false: the
# cockpit can quit OBS without a question popping up.
setkey() {   # $1 file  $2 key  $3 value  (in [General])
  local f="$1"
  touch "$f"
  if grep -q "^$2=" "$f"; then sed -i '' "s/^$2=.*/$2=$3/" "$f"
  elif grep -q '^\[General\]' "$f"; then sed -i '' "s/^\[General\]\$/[General]\\
$2=$3/" "$f"
  else printf '[General]\n%s=%s\n' "$2" "$3" >> "$f"; fi
}
for ini in global.ini user.ini; do
  setkey "$DIR/$ini" FirstRun true
  setkey "$DIR/$ini" MacOSPermissionsDialogLastShown 1
done
setkey "$DIR/user.ini" ConfirmOnExit false
echo "OBS first-run wizard and permission window: skipped"
echo
echo "Last, once: System Settings > Privacy & Security > Screen & System Audio Recording: turn on OBS;"
echo "and Microphone: turn on OBS. Then quit OBS. The cockpit starts OBS and builds the scene itself."
