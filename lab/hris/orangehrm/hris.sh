#!/usr/bin/env bash
# =============================================================================
# hris.sh - run OrangeHRM (the lab's HR system) on this Mac, in Colima.
# -----------------------------------------------------------------------------
#   ./hris.sh up         start it (makes the passwords on the first run)
#   ./hris.sh install    first run only: OrangeHRM's own CLI installer
#   ./hris.sh connector  create the connector's read-only view and account
#   ./hris.sh seed       first run only: load the Contoso roster (hr_feed.csv)
#   ./hris.sh status     is it up, and how many workers it holds
#   ./hris.sh down       stop it (data kept in the Docker volumes)
#   ./hris.sh destroy    stop it and delete all its data
#
# WHY each step: ADR 0028 and README.md.
#
# SECRETS. Four passwords, each made here with openssl and kept ONLY in the
# macOS login Keychain:
#   contoso-hris-db-root     MariaDB root (used by install/connector/seed)
#   contoso-hris-db-app      OrangeHRM's own database account
#   contoso-hris-admin       OrangeHRM "Admin" (the HR administrator sign-in)
#   contoso-hris-connector   the connector's read-only database account
# They go in through `security -i` on stdin (never argv), are read with
# `security find-generic-password -w` into a variable (never -g), and reach
# the containers as compose secret files or over stdin. Nothing prints them.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
export DOCKER_CONTEXT="${HRIS_DOCKER_CONTEXT:-colima}"
ROOT="$(git rev-parse --show-toplevel)"
# The roster to load: the one on hr-feed (what Entra holds today), unless
# HRIS_ROSTER names a file.
ROSTER="${HRIS_ROSTER:-}"

kc_get() { security find-generic-password -s "$1" -w 2>/dev/null; }
kc_make() { # $1 service, $2 label. Makes the item once; never overwrites.
  if kc_get "$1" >/dev/null; then return; fi
  # OrangeHRM's password rule: upper, lower, digit, symbol, 8+ characters.
  local pw; pw="$(openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-24)Aa1#"
  printf 'add-generic-password -s %s -a contoso-hris -l "%s" -w %s\n' "$1" "$2" "$pw" | security -i >/dev/null
  unset pw
  echo "Made Keychain item $1."
}
sql_root() { # SQL on stdin, as MariaDB root. The password goes in a client
  # option file through stdin, never argv or the environment.
  local pw; pw="$(kc_get contoso-hris-db-root)"
  { printf '[client]\nuser=root\npassword="%s"\n' "$pw"; } | docker compose exec -T db sh -c 'umask 077; cat > /tmp/.root.cnf'
  unset pw
  docker compose exec -T db sh -c 'mariadb --defaults-extra-file=/tmp/.root.cnf "$@"; rc=$?; rm -f /tmp/.root.cnf; exit $rc' -- "$@"
}

case "${1:-}" in
  up)
    kc_make contoso-hris-db-root "Contoso HRIS: MariaDB root"
    kc_make contoso-hris-db-app "Contoso HRIS: OrangeHRM's own DB account"
    kc_make contoso-hris-admin "Contoso HRIS: OrangeHRM Admin sign-in"
    kc_make contoso-hris-connector "Contoso HRIS: connector read-only DB account"
    if ! docker image inspect contoso-hris-orangehrm:5.9 >/dev/null 2>&1; then
      DOCKER_BUILDKIT=0 docker build -q -t contoso-hris-orangehrm:5.9 .
    fi
    HRIS_DB_ROOT="$(kc_get contoso-hris-db-root)" docker compose up -d --wait
    echo "OrangeHRM: http://127.0.0.1:8585 (this Mac only)."
    ;;
  install)
    if docker compose exec -T hris test -s /var/www/html/lib/confs/Conf.php; then echo "Already installed."; exit 0; fi
    root="$(kc_get contoso-hris-db-root)"; app="$(kc_get contoso-hris-db-app)"; admin="$(kc_get contoso-hris-admin)"
    # OrangeHRM reads installer/cli_install_config.yaml. We write ours over
    # stdin, run the installer, then delete it. registrationConsent: false =
    # no install report is sent to OrangeHRM Inc.
    cat <<YAML | docker compose exec -T hris sh -c 'umask 077; cat > installer/cli_install_config.yaml'
database:
  hostName: db
  hostPort: 3306
  databaseName: orangehrm
  privilegedDatabaseUser: root
  privilegedDatabasePassword: '$root'
  useSameDbUserForOrangeHRM: n
  orangehrmDatabaseUser: orangehrm
  orangehrmDatabasePassword: '$app'
  isExistingDatabase: n
  enableDataEncryption: n
organization:
  name: Contoso Health
  country: US
admin:
  adminUserName: Admin
  adminPassword: '$admin'
  adminEmployeeFirstName: HR
  adminEmployeeLastName: Administrator
  workEmail: hr.admin@contosohealthlab.com
  contactNumber: ~
  registrationConsent: false
license:
  agree: y
YAML
    unset root app admin
    docker compose exec -T hris sh -c 'php installer/cli_install.php; rc=$?; rm -f installer/cli_install_config.yaml; exit $rc'
    docker compose exec -T hris chown -R www-data:www-data /var/www/html/lib/confs /var/www/html/src/cache /var/www/html/src/log 2>/dev/null || true
    ;;
  connector)
    # The connector's database account can read ONE view and nothing else
    # (ADR 0028, "least data"). The view has the nine HR fields the
    # provisioning feed needs. No date of birth, address, salary, ID number,
    # contact detail or note can reach the connector: MariaDB refuses them.
    pw="$(kc_get contoso-hris-connector)"
    { cat connector-view.sql
      printf "CREATE USER IF NOT EXISTS 'hr_connector'@'%%' IDENTIFIED BY '%s';\n" "$pw"
      printf "ALTER USER 'hr_connector'@'%%' IDENTIFIED BY '%s';\n" "$pw"
      cat <<'SQL'
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'hr_connector'@'%';
GRANT SELECT ON hr_feed.v_worker_feed TO 'hr_connector'@'%';
FLUSH PRIVILEGES;
SQL
    } | sql_root
    unset pw
    echo "Connector account hr_connector can read hr_feed.v_worker_feed only."
    ;;
  seed)
    n="$(echo 'SELECT COUNT(*) FROM ohrm_subunit WHERE level > 0;' | sql_root orangehrm -N)"
    if [ "$n" != "0" ]; then echo "Already seeded ($n departments). Nothing done."; exit 0; fi
    if [ -z "$ROSTER" ]; then
      ROSTER="$(mktemp)"; trap 'rm -f "$ROSTER"' EXIT
      git -C "$ROOT" fetch -q origin hr-feed
      git -C "$ROOT" show origin/hr-feed:lab/scripts/mock-hr/hr_feed.csv > "$ROSTER"
    fi
    node seed.mjs "$ROSTER" | sql_root orangehrm
    echo "Seeded $(grep -c '^[0-9]' "$ROSTER") workers."
    ;;
  status)
    docker compose ps --format '{{.Service}} {{.State}} {{.Ports}}'
    echo "SELECT COUNT(*) AS workers, SUM(termination_id IS NULL) AS current FROM hs_hr_employee WHERE purged_at IS NULL;" | sql_root orangehrm --table
    ;;
  down) docker compose stop ;;
  destroy) docker compose down -v ;;
  *) sed -n '5,13p' "$0"; exit 2 ;;
esac
