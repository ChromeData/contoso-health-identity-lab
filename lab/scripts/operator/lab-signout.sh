#!/usr/bin/env bash
# =============================================================================
# lab-signout.sh - end the operator's local session
# -----------------------------------------------------------------------------
# Signs the operator's az profile out and deletes the session copy of the
# private key. The Keychain item stays; lab-signin.sh starts a new session.
# AWS sessions already issued run out on their own within the hour.
# =============================================================================
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"

az logout --only-show-errors 2>/dev/null || true
az account clear --only-show-errors 2>/dev/null || true
rm -f "$OP_PEM"
echo "Operator signed out; session key removed."
