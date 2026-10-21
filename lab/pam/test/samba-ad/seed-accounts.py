#!/usr/bin/env python3
# =============================================================================
# seed-accounts.py - give the test DC the account layout of the real DC01
# (lab/scripts/dc/02-Configure-Domain.ps1), offline against sam.ldb, before
# samba starts. Run once by the entrypoint; nothing here prints a password.
#
#   OU=ServiceAccounts     svc-vault-rotator  Vault bind/reconcile account
#                          svc-backup         Vault STATIC role
#   OU=PrivilegedAccounts  tier0-admin-01/02  Vault LIBRARY set, Domain Admins,
#                                             "sensitive, cannot be delegated"
#   CN == sAMAccountName for all four, password never expires.
#
# PLUS a discovery population (PAM ops pack: discover -> onboard -> rotate ->
# reconcile), one account per finding a real AD discovery turns up:
#   svc-pam-discovery  plain Domain User the discovery binds as (read-only)
#   svc-sql01          SPN MSSQLSvc/...  -> static role, but its dependencies
#                      are UNRESOLVED in the test map: onboarding holds it
#   svc-iis-app        SPN HTTP/...      -> static role, dependencies resolved
#   svc-legacy-da      SPN + Domain Admins: Kerberoastable Tier 0 -> exception
#   t1-srvadmin-01/02  Tier1-Server-Admins (a custom tier-1 group) -> library
#   t0-stale-admin     Domain Admins, last logon 400 days ago -> exception
#   t0-never-admin     Administrators via a NESTED group, created 200 days
#                      ago, never logged on -> exception (proves nesting works)
#   former-admin-01    adminCount=1 but in no privileged group: SDProp's
#                      leftover ("orphaned adminCount") -> exception
# Samba does not run SDProp, so adminCount=1 is set here on members of the
# protected groups, as Windows would within an hour. lastLogonTimestamp and
# whenCreated are backdated directly in sam.ldb (system session, plus the
# "relax" control for whenCreated) - only possible offline, test DC only.
#
# THE ONE DELIBERATE DIFFERENCE: svc-vault-rotator is made a Domain Admin here.
# The real DC grants it only Reset Password + pwdLastSet/lockoutTime writes,
# on OU=ServiceAccounts (inherited) and on AdminSDHolder (for the Domain Admin
# tier0 accounts, because SDProp overwrites OU delegation on protected
# objects). Samba does not run SDProp, so mirroring that ACL here would prove
# nothing about the real DC; Domain Admin is the simplest honest stand-in.
#
# Secrets (compose secrets, from lab/pam/.secrets/test/, 0600):
#   samba_admin_password        -> Administrator
#   svc_vault_rotator_password  -> svc-vault-rotator (Vault's bind password)
#   svc_backup_password         -> svc-backup's PRE-onboarding password, so
#                                  e2e.sh can prove Vault rotated it away
#   svc_pam_discovery_password  -> svc-pam-discovery (discover.sh binds with it)
# tier0-admin-01/02 get random passwords that are never stored - Vault sets
# them when the library is created, exactly like the real DC. So do all the
# discovery-population accounts.
#
# BULK MODE (test/e2e-scale.sh - "500 accounts: how did you onboard them?"):
#   seed-accounts.py --bulk N [--noise M] [--seed S]
# Run on a DC that already has the layout above (the entrypoint seeded it);
# samba may be running (local sam.ldb writes, as samba-tool does). Adds N
# synthetic PAM-relevant accounts in a fixed mix (BULK_MIX: SPN service
# accounts, batch run-as accounts, tier-1/tier-0 admins in tiered OUs and
# through NESTED groups - some outside the PAM OUs, stale and never-used
# privileged accounts, orphaned adminCount, disabled admins, Kerberoastable
# Tier-0 service accounts) plus M ordinary staff users that discovery must
# NOT report. Each eligible account also gets a dependency record in the
# accounts-dependencies.json shape: resolved, UNRESOLVED (onboarding must
# hold it) or none at all (unknown is not "none": held too), and a few
# vaulted ones get a consumer a later re-scan finds ("drift": rotation must
# then be refused). Deterministic for a given --seed.
# stdout: one JSON manifest (account, DN, category, what discovery must
# propose, dependency record); progress on stderr. Passwords: random, never
# stored or printed - Vault sets the real ones on onboarding.
# =============================================================================
import argparse
import json
import random
import secrets
import sys
import time

import ldb
from samba.auth import system_session
from samba.dsdb import UF_NOT_DELEGATED
from samba.param import LoadParm
from samba.samdb import SamDB


def secret(name: str) -> str:
    with open(f"/run/secrets/{name}", encoding="utf-8") as fh:
        value = fh.read().rstrip("\r\n")
    if not value:
        raise SystemExit(f"secret {name} is empty")
    return value


def random_password() -> str:
    # Upper + lower + digit + symbol: satisfies AD complexity.
    return f"Rn-{secrets.token_hex(16)}-7Q"


lp = LoadParm()
lp.load_default()
samdb = SamDB(url=lp.samdb_url(), session_info=system_session(), lp=lp)
base = str(samdb.domain_dn())

# Progress lines: stdout in base mode (the entrypoint logs them), stderr in
# bulk mode (stdout carries the JSON manifest there).
OUT = sys.stdout


def ensure_ou(name: str) -> None:
    # name: "Staff", or a nested "Tier1,OU=PrivilegedAccounts" (parent first)
    try:
        samdb.create_ou(f"OU={name},{base}")
        print(f"  + OU={name}", file=OUT)
    except ldb.LdbError as err:
        if err.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise


def ensure_user(sam: str, ou: str, description: str, password: str) -> None:
    if samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                    expression=f"(sAMAccountName={sam})", attrs=["dn"]):
        print(f"  = {sam} exists", file=OUT)
        return
    samdb.newuser(sam, password, useusernameascn=True, userou=f"OU={ou}",
                  description=description)
    # PasswordNeverExpires, as New-ADUser -PasswordNeverExpires on the real DC.
    samdb.setexpiry(f"(sAMAccountName={sam})", 0, no_expiry_req=True)
    print(f"  + CN={sam},OU={ou}", file=OUT)


def dn_of(sam: str) -> str:
    return str(samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                            expression=f"(sAMAccountName={sam})", attrs=["dn"])[0].dn)


def modify_dn(dn: str, controls=None, **attrs) -> None:
    msg = ldb.Message()
    msg.dn = ldb.Dn(samdb, dn)
    for name, value in attrs.items():
        values = value if isinstance(value, list) else [value]
        msg[name] = ldb.MessageElement([str(v) for v in values], ldb.FLAG_MOD_REPLACE, name)
    samdb.modify(msg, controls=controls or [])


def replace_attrs(sam: str, controls=None, **attrs) -> None:
    modify_dn(dn_of(sam), controls=controls, **attrs)


def filetime(days_ago: float) -> int:
    # Windows FILETIME: 100 ns ticks since 1601-01-01 UTC.
    return int((time.time() - days_ago * 86400 + 11644473600) * 10_000_000)


def generalized_time(days_ago: float) -> str:
    return time.strftime("%Y%m%d%H%M%S.0Z", time.gmtime(time.time() - days_ago * 86400))


def ensure_group(name: str, ou: str, description: str) -> None:
    if samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                    expression=f"(&(objectClass=group)(cn={name}))", attrs=["dn"]):
        return
    samdb.newgroup(name, groupou=f"OU={ou}", description=description)
    print(f"  + group {name}", file=OUT)


def seed_base() -> None:
    samdb.setpassword("(sAMAccountName=Administrator)", secret("samba_admin_password"))

    ensure_ou("ServiceAccounts")
    ensure_ou("PrivilegedAccounts")

    ensure_user("svc-vault-rotator", "ServiceAccounts",
                "Vault LDAP secrets engine bind/reconcile account (CPM role). TEST DC: Domain Admin.",
                secret("svc_vault_rotator_password"))
    ensure_user("svc-backup", "ServiceAccounts",
                "Nightly backup service account - Vault STATIC role (scheduled rotation).",
                secret("svc_backup_password"))
    for name in ("tier0-admin-01", "tier0-admin-02"):
        ensure_user(name, "PrivilegedAccounts",
                    "Tier-0 admin - Vault LIBRARY (exclusive check-out), sessions recorded by Guacamole.",
                    random_password())
        samdb.toggle_userAccountFlags(f"(sAMAccountName={name})", UF_NOT_DELEGATED, on=True)

    # Domain Admins: the tier0 pair (as on DC01) + the rotator (test-only, see header).
    samdb.add_remove_group_members(
        "Domain Admins", ["tier0-admin-01", "tier0-admin-02", "svc-vault-rotator"],
        add_members_operation=True)
    print("  Domain Admins += tier0-admin-01, tier0-admin-02, svc-vault-rotator")

    # --- discovery population ----------------------------------------------------
    ensure_user("svc-pam-discovery", "ServiceAccounts",
                "PAM discovery bind account - read-only Domain User.",
                secret("svc_pam_discovery_password"))
    ensure_user("svc-sql01", "ServiceAccounts", "SQL Server service account (sql01).", random_password())
    replace_attrs("svc-sql01", servicePrincipalName=["MSSQLSvc/sql01.corp.test.local:1433", "MSSQLSvc/sql01.corp.test.local"])
    ensure_user("svc-iis-app", "ServiceAccounts", "Clinical portal app pool identity (app01).", random_password())
    replace_attrs("svc-iis-app", servicePrincipalName="HTTP/app01.corp.test.local")
    ensure_user("svc-legacy-da", "ServiceAccounts", "Legacy agent running as a domain admin.", random_password())
    replace_attrs("svc-legacy-da", servicePrincipalName="HOST/legacy01.corp.test.local")

    ensure_group("Tier1-Server-Admins", "PrivilegedAccounts", "Tier 1: member-server administrators")
    ensure_group("Tier0-Nested-Ops", "PrivilegedAccounts", "Nested into BUILTIN\\Administrators")
    for name in ("t1-srvadmin-01", "t1-srvadmin-02"):
        ensure_user(name, "PrivilegedAccounts", "Tier-1 server admin - Vault LIBRARY tier1-admins.", random_password())
    samdb.add_remove_group_members("Tier1-Server-Admins", ["t1-srvadmin-01", "t1-srvadmin-02"], add_members_operation=True)

    ensure_user("t0-stale-admin", "PrivilegedAccounts", "Domain admin nobody has used in a year.", random_password())
    ensure_user("t0-never-admin", "PrivilegedAccounts", "Admin created for a project, never used.", random_password())
    ensure_user("former-admin-01", "PrivilegedAccounts", "Was a domain admin, removed from the group.", random_password())
    samdb.add_remove_group_members("Domain Admins", ["t0-stale-admin", "svc-legacy-da"], add_members_operation=True)
    samdb.add_remove_group_members("Tier0-Nested-Ops", ["t0-never-admin"], add_members_operation=True)
    samdb.add_remove_group_members("Administrators", ["Tier0-Nested-Ops"], add_members_operation=True)

    # SDProp stand-in: adminCount=1 on protected-group members, and on the
    # account that LEFT the group (the orphan discovery must flag).
    for sam in ("tier0-admin-01", "tier0-admin-02", "svc-vault-rotator", "t0-stale-admin",
                "svc-legacy-da", "t0-never-admin", "former-admin-01"):
        replace_attrs(sam, adminCount="1")
    replace_attrs("t0-stale-admin", lastLogonTimestamp=filetime(400))
    replace_attrs("t0-never-admin", controls=["relax:0"], whenCreated=generalized_time(200))
    print("  discovery population: svc-pam-discovery, svc-sql01, svc-iis-app, svc-legacy-da, "
          "t1-srvadmin-01/02, t0-stale-admin, t0-never-admin, former-admin-01")


# --- bulk mode ----------------------------------------------------------------------
# category, percent of N, what it is. The percentages add up to 100; the
# rounding remainder goes to svc_spn, so the population is exactly N.
BULK_MIX = [
    ("svc_spn",           36, "service account with SPNs (MSSQLSvc/HTTP/HOST) -> static role svc/<sam>"),
    ("svc_batch",         12, "scheduled-job run-as account in OU=ServiceAccounts, no SPN -> static role svc/<sam>"),
    ("svc_tier1",          2, "monitoring agent with an SPN in Tier1-Server-Admins -> static role tier1/<sam>"),
    ("t1_admin",          16, "tier-1 server admin in OU=Tier1,OU=PrivilegedAccounts -> library tier1-admins"),
    ("t1_nested",          4, "staff account in OU=Staff, admin through NESTED Tier1-App-Admins -> library tier1-admins"),
    ("t0_admin",           4, "domain admin in OU=Tier0,OU=PrivilegedAccounts -> library tier0-admins"),
    ("t0_nested",          2, "admin through NESTED Tier0-Infra-Ops (in Administrators) -> library tier0-admins"),
    ("stale_priv",         8, "privileged, last logon 120-900 days ago -> exception (stale)"),
    ("never_priv",         5, "privileged, created 45-400 days ago, never logged on -> exception (never used)"),
    ("orphan_admincount",  6, "adminCount=1 but in no privileged group -> exception (orphaned adminCount)"),
    ("disabled_priv",      3, "disabled account still in Tier1-Server-Admins -> exception (disabled)"),
    ("kerberoast_t0",      2, "service account with an SPN in Domain Admins -> exception (Kerberoastable Tier 0)"),
]

# Dependency mix per eligible category, percent (unresolved, no record); the rest are clear.
DEP_MIX = {
    "svc_spn": (25, 15), "svc_batch": (30, 20), "svc_tier1": (30, 0),
    "t1_admin": (10, 5), "t1_nested": (10, 5), "t0_admin": (10, 0), "t0_nested": (10, 0),
}

# app, SPN service class, port, consumer types a dependency scan finds for it
APPS = [
    ("sql", "MSSQLSvc", 1433, ["windows-service", "scheduled-task", "connection-string"]),
    ("web", "HTTP", None, ["iis-app-pool", "connection-string"]),
    ("hl7", "HOST", None, ["windows-service"]),
    ("pacs", "HTTP", None, ["iis-app-pool", "windows-service"]),
    ("lis", "MSSQLSvc", 1433, ["windows-service", "connection-string"]),
    ("ris", "HTTP", None, ["iis-app-pool"]),
    ("rx", "HTTP", None, ["iis-app-pool", "scheduled-task"]),
    ("fax", "HOST", None, ["windows-service"]),
    ("print", "HOST", None, ["windows-service"]),
    ("bi", "MSSQLSvc", 1433, ["windows-service", "scheduled-task"]),
    ("sccm", "HOST", None, ["windows-service", "scheduled-task"]),
    ("bkp", "HOST", None, ["scheduled-task", "windows-service"]),
]
SURNAMES = ["okafor", "patel", "nguyen", "garcia", "mwangi", "osei", "carter", "reyes", "nair",
            "bello", "kim", "silva", "haddad", "novak", "jensen", "rossi", "tanaka", "murphy",
            "dubois", "ahmed", "kowalski", "mensah", "lopez", "fischer", "ivanova", "obi",
            "santos", "walsh", "cohen", "yilmaz", "brennan", "achebe", "lindqvist", "moreau"]
RESOLUTIONS = [
    "reads the password from Vault at run time (Vault Agent template, re-rendered on rotation)",
    "reads the password from Vault at run time (application calls the Vault API)",
    "decommissioned: consumer removed in the last dependency review",
]


def pct(count: int, percent: int) -> int:
    return (count * percent + 50) // 100   # round half up, integers only


def expect(tier, action, reason=None) -> dict:
    return {"tier": tier, "action": action, "reason": reason}


def consumer(rng, app: str, host: str, ctype: str, resolved: bool) -> dict:
    name = {
        "windows-service": f"{app.upper()}Svc",
        "iis-app-pool": f"{app.capitalize()}Pool",
        "scheduled-task": f"\\Contoso\\{app.capitalize()}Nightly",
        "connection-string": f"{app}.config (ConnectionStrings)",
    }[ctype]
    c = {"type": ctype, "host": host, "name": name, "owner": f"{app}-team", "resolved": resolved}
    if resolved:
        c["resolution"] = rng.choice(RESOLUTIONS)
    return c


def seed_bulk(n: int, noise: int, seed: int) -> dict:
    t0 = time.time()
    rng = random.Random(seed)
    for name in ("svc-pam-discovery", "Tier1-Server-Admins", "Tier0-Nested-Ops"):
        if not samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression=f"(sAMAccountName={name})", attrs=["dn"]):
            raise SystemExit(f"bulk mode needs the base layout first ({name} missing): start the DC normally, then --bulk")
    if samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression="(description=BULK*)", attrs=["dn"]):
        raise SystemExit("this DC already has a bulk population - start from a fresh DC volume")

    for ou in ("Staff", "Tier0,OU=PrivilegedAccounts", "Tier1,OU=PrivilegedAccounts"):
        ensure_ou(ou)
    ensure_group("Tier1-App-Admins", "PrivilegedAccounts", "Application admins - nested into Tier1-Server-Admins")
    ensure_group("Tier0-Infra-Ops", "PrivilegedAccounts", "Infrastructure ops - nested into BUILTIN\\Administrators")
    samdb.add_remove_group_members("Tier1-Server-Admins", ["Tier1-App-Admins"], add_members_operation=True)
    samdb.add_remove_group_members("Administrators", ["Tier0-Infra-Ops"], add_members_operation=True)

    counts = {c: n * p // 100 for c, p, _ in BULK_MIX}
    counts["svc_spn"] += n - sum(counts.values())

    accounts = []
    members = {"Domain Admins": [], "Tier1-Server-Admins": [], "Tier1-App-Admins": [], "Tier0-Infra-Ops": []}
    pending = []          # (dn, controls, attrs): applied once every account exists
    seq = {"human": 0}

    def new_account(sam, ou, category, desc, exp, dept, extra=None):
        samdb.newuser(sam, random_password(), useusernameascn=True, userou=f"OU={ou}",
                      description=f"BULK {desc}", department=dept)
        rec = {"sam": sam, "dn": f"CN={sam},OU={ou},{base}", "category": category, "expect": exp,
               "deps_status": None, "dependencies": None, "drift": None}
        rec.update(extra or {})
        accounts.append(rec)
        if len(accounts) % 100 == 0:
            print(f"  {len(accounts)}/{n} accounts", file=OUT)
        return rec

    def human_name(prefix):
        seq["human"] += 1
        return f"{prefix}-{SURNAMES[seq['human'] % len(SURNAMES)]}{seq['human']:03d}"

    def svc_name(app):
        seq[app] = seq.get(app, 0) + 1
        return f"svc-{app}-{seq[app]:03d}", f"{app}{seq[app]:03d}.corp.test.local"

    for category, _, desc in BULK_MIX:
        for i in range(counts[category]):
            if category in ("svc_spn", "svc_tier1", "kerberoast_t0"):
                if category == "svc_spn":
                    app, cls, port, ctypes = APPS[i % len(APPS)]
                elif category == "svc_tier1":
                    app, cls, port, ctypes = "mgmt", "HTTP", None, ["windows-service"]
                else:
                    app, cls, port, ctypes = "agent", "HOST", None, ["windows-service"]
                sam, host = svc_name(app)
                spns = [f"{cls}/{host}:{port}", f"{cls}/{host}"] if port else [f"{cls}/{host}"]
                exp = {"svc_spn": expect("svc", "static"), "svc_tier1": expect("tier1", "static"),
                       "kerberoast_t0": expect("tier0", "exception", "Kerberoastable")}[category]
                rec = new_account(sam, "ServiceAccounts", category, desc, exp, "IT Infrastructure",
                                  {"app": app, "host": host, "consumer_types": ctypes})
                attrs = {"servicePrincipalName": spns, "lastLogonTimestamp": filetime(rng.uniform(0, 14))}
                if category == "svc_tier1":
                    members["Tier1-Server-Admins"].append(sam)
                if category == "kerberoast_t0":
                    members["Domain Admins"].append(sam)
                    attrs["adminCount"] = "1"
                pending.append((rec["dn"], None, attrs))
            elif category == "svc_batch":
                sam, _ = svc_name("job")
                rec = new_account(sam, "ServiceAccounts", category, desc, expect("svc", "static"), "IT Infrastructure",
                                  {"app": "job", "host": f"batch{rng.randint(1, 20):02d}.corp.test.local",
                                   "consumer_types": ["scheduled-task"]})
                pending.append((rec["dn"], None, {"lastLogonTimestamp": filetime(rng.uniform(0, 3))}))
            else:
                t0_side = category in ("t0_admin", "t0_nested", "orphan_admincount") or \
                    (category == "stale_priv" and i % 4 == 0)
                tier = "tier0" if t0_side else "tier1"
                sam = human_name("a0" if t0_side else "a1")
                if category == "t1_nested":
                    ou = "Staff"
                else:
                    ou = "Tier0,OU=PrivilegedAccounts" if t0_side else "Tier1,OU=PrivilegedAccounts"
                exp = {
                    "t1_admin": expect("tier1", "library"), "t1_nested": expect("tier1", "library"),
                    "t0_admin": expect("tier0", "library"), "t0_nested": expect("tier0", "library"),
                    "stale_priv": expect(tier, "exception", "stale privileged account (last logon"),
                    "never_priv": expect("tier1", "exception", "never logged on"),
                    "orphan_admincount": expect(None, "exception", "orphaned adminCount"),
                    "disabled_priv": expect("tier1", "exception", "disabled account"),
                }[category]
                rec = new_account(sam, ou, category, desc, exp,
                                  "Clinical Systems" if category == "t1_nested" else "IT Operations")
                if category == "t1_nested":
                    members["Tier1-App-Admins"].append(sam)
                elif category == "t0_nested":
                    members["Tier0-Infra-Ops"].append(sam)
                elif category != "orphan_admincount":
                    members["Domain Admins" if t0_side else "Tier1-Server-Admins"].append(sam)
                attrs = {}
                if t0_side:
                    attrs["adminCount"] = "1"           # SDProp stand-in (and the orphan's leftover)
                if category == "stale_priv":
                    attrs["lastLogonTimestamp"] = filetime(rng.uniform(120, 900))
                elif category == "never_priv":
                    pending.append((rec["dn"], ["relax:0"], {"whenCreated": generalized_time(rng.uniform(45, 400))}))
                else:
                    attrs["lastLogonTimestamp"] = filetime(rng.uniform(0, 20))
                if attrs:
                    pending.append((rec["dn"], None, attrs))
                if category == "disabled_priv":
                    samdb.disable_account(f"(sAMAccountName={sam})")

    for group, sams in members.items():
        for i in range(0, len(sams), 100):
            samdb.add_remove_group_members(group, sams[i:i + 100], add_members_operation=True)
        if sams:
            print(f"  {group} += {len(sams)}", file=OUT)
    for dn, controls, attrs in pending:
        modify_dn(dn, controls=controls, **attrs)

    # Dependency records (accounts-dependencies.json shape) for the eligible accounts.
    for category, (unres_pct, none_pct) in DEP_MIX.items():
        recs = [a for a in accounts if a["category"] == category]
        n_unres, n_none = pct(len(recs), unres_pct), pct(len(recs), none_pct)
        statuses = ["unresolved"] * n_unres + ["unknown"] * n_none + ["clear"] * (len(recs) - n_unres - n_none)
        rng.shuffle(statuses)
        for rec, status in zip(recs, statuses):
            rec["deps_status"] = status
            if status == "unknown":
                continue                               # NO record: nobody has looked
            if "consumer_types" not in rec:           # a human admin: [] = reviewed, no run-as use
                rec["dependencies"] = [] if status == "clear" else [{
                    "type": "scheduled-task", "host": f"app{rng.randint(1, 40):02d}.corp.test.local",
                    "name": f"\\Contoso\\RunAs-{rec['sam']}", "owner": "app-team", "resolved": False}]
                continue
            k = rng.randint(1, min(3, len(rec["consumer_types"]) + 1))
            hosts = [rec["host"]] + [f"{rec['app']}{rng.randint(100, 199)}.corp.test.local" for _ in range(k - 1)]
            deps = [consumer(rng, rec["app"], h, rng.choice(rec["consumer_types"]), True) for h in hosts]
            if status == "unresolved":
                deps[0] = consumer(rng, rec["app"], hosts[0], deps[0]["type"], False)
            rec["dependencies"] = deps
    # Drift: clear (so: vaulted) service accounts a re-scan AFTER onboarding finds a new consumer for.
    clear_static = [a for a in accounts if a["expect"]["action"] == "static" and a["deps_status"] == "clear"]
    for rec in rng.sample(clear_static, min(len(clear_static), max(1, n * 2 // 100))):
        rec["drift"] = {"type": "scheduled-task", "host": f"rpt{rng.randint(1, 9):02d}.corp.test.local",
                        "name": "\\Contoso\\ReportExtract", "owner": "reporting-team", "resolved": False,
                        "found_by": "dependency re-scan after onboarding"}
    for rec in accounts:
        for key in ("app", "host", "consumer_types"):
            rec.pop(key, None)

    noise_sams = []
    for i in range(noise):
        sam = f"{chr(97 + i % 26)}{SURNAMES[i % len(SURNAMES)]}{i + 1:03d}"
        samdb.newuser(sam, random_password(), useusernameascn=True, userou="OU=Staff",
                      description="BULK staff user (not privileged)", department="Nursing")
        modify_dn(f"CN={sam},OU=Staff,{base}", lastLogonTimestamp=filetime(rng.uniform(0, 30)))
        noise_sams.append(sam)
    secs = time.time() - t0
    print(f"  bulk population: {n} PAM-relevant accounts + {noise} staff users in {secs:.1f}s", file=OUT)

    return {"schema": "contoso-pam/scale-manifest/v1", "seed": seed, "bulk": n, "noise": noise,
            "base_dn": base, "mix": {c: counts[c] for c, _, _ in BULK_MIX},
            "seconds": round(secs, 3), "accounts": accounts, "noise_accounts": noise_sams}


def main() -> None:
    global OUT
    ap = argparse.ArgumentParser(description="Seed the Samba test DC (base layout, or --bulk N on top of it).")
    ap.add_argument("--bulk", type=int, metavar="N", help="add N synthetic PAM-relevant accounts (1-5000)")
    ap.add_argument("--noise", type=int, default=0, metavar="M", help="with --bulk: M ordinary staff users")
    ap.add_argument("--seed", type=int, default=20261020, help="with --bulk: random seed (deterministic mix)")
    args = ap.parse_args()
    if args.bulk is None:
        seed_base()
        return
    if not 1 <= args.bulk <= 5000 or not 0 <= args.noise <= 20000:
        raise SystemExit("--bulk must be 1-5000 and --noise 0-20000")
    OUT = sys.stderr
    json.dump(seed_bulk(args.bulk, args.noise, args.seed), sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
