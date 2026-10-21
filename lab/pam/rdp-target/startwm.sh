#!/bin/sh
# The whole RDP "desktop": one light xterm filling the 1024x768 screen, so it
# sits under the pointer (there is no window manager: keyboard focus follows
# the pointer) and the recording shows a full screen, not text on black that
# guacd never has to draw. Typing `exit` closes it, which ends the session;
# xrdp then drops the connection, so a scripted session through Guacamole
# ends cleanly.
# shellcheck disable=SC2016 # the -c script is expanded by the session's bash, not here
exec xterm -title "rdp-target - Linux xrdp stand-in for DC01 (lab)" -geometry 168x57+0+0 \
  -bg "#f2f2f2" -fg "#101010" -e /bin/bash -c '
    realm=$(sed -n "s/^ *default_realm *= *//p" /etc/krb5.conf)
    printf "rdp-target: LINUX xrdp STAND-IN for an RDP session to DC01 (lab only)\n"
    printf "%s signed in with the AD password (Kerberos, realm %s)\n\n" "$(id -un)" "$realm"
    exec /bin/bash --noprofile --norc -i'
