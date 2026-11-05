#!/bin/sh
# The whole RDP "desktop": one light xterm filling the 1024x768 screen, so it
# sits under the pointer (there is no window manager: keyboard focus follows
# the pointer) and the recording shows a full screen, not text on black that
# guacd never has to draw. Typing `exit` closes it, which ends the session;
# xrdp then drops the connection, so a scripted session through Guacamole
# ends cleanly.
#
# READY MARKER (~/.rdp-session-ready): written once keys typed through RDP
# reach this shell, so a scripted session (test/e2e.sh -> test/guac_tunnel.py
# --ready-cmd) types then instead of after a fixed wait. "The shell process
# exists" is NOT that moment: xterm starts its child before it maps its window
# (xterm main.c: spawnXTerm() runs before VTRun(), and VTRun() maps the window
# via set_vt_visibility()), and with no window manager a key sent before the
# map lands on the root window and is lost. So the shell asks the terminal
# for its Primary Device Attributes (CSI c): xterm answers only from its
# event loop, which it enters after requesting the map, so an answer means
# the window is there to take keys. Keys typed after that wait in the pty
# until bash reads them. No answer within 30 s: no marker, and the harness
# reports the target as never ready (it does not type into the void).
# shellcheck disable=SC2016 # the -c script is expanded by the session's bash, not here
exec xterm -title "rdp-target - Linux xrdp stand-in for DC01 (lab)" -geometry 168x57+0+0 \
  -bg "#f2f2f2" -fg "#101010" -e /bin/bash -c '
    realm=$(sed -n "s/^ *default_realm *= *//p" /etc/krb5.conf)
    printf "rdp-target: LINUX xrdp STAND-IN for an RDP session to DC01 (lab only)\n"
    printf "%s signed in with the AD password (Kerberos, realm %s)\n\n" "$(id -un)" "$realm"
    rm -f "$HOME/.rdp-session-ready"
    printf "\033[c"
    if IFS= read -r -s -d c -t 30 _; then : > "$HOME/.rdp-session-ready"; fi
    exec /bin/bash --noprofile --norc -i'
