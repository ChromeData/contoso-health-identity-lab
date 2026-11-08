#!/usr/bin/env python3
# =============================================================================
# discover.py - privileged-account discovery against Active Directory
# ("accounts discovery" in PAM terms).
#
# Runs INSIDE the pam-tools container (../discover.sh starts it), so it reaches
# the DC through the same extra_hosts mapping and AD root CA as Vault.
# Read-only: binds as a plain Domain User (svc-pam-discovery), never as the
# Tier-0 rotator - discovery must not need the keys it is looking for.
#
# What counts as a candidate (any one is enough):
#   * transitive member of a privileged group in pam-policy.json, found with
#     LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) so nested groups
#     count, PLUS users whose primaryGroupID is that group's RID (memberOf
#     never lists the primary group - a classic blind spot of naive scripts)
#   * has a servicePrincipalName (Kerberoastable: offline-crackable TGS)
#   * adminCount=1 (SDProp touched it: protected now, or ORPHANED if it left
#     the protected groups but kept the flag and the hardened ACL)
#   * lives in an OU the policy lists as service/privileged accounts
# Computers and gMSAs are out of scope (objectCategory=person): AD rotates
# machine and gMSA passwords itself.
#
# Classification (first match wins), output as JSON on stdout:
#   exception  policy exclusion | disabled | orphaned adminCount | stale or
#              never-used privileged account | Tier-0 account with an SPN
#   library    a human privileged account -> its tier's library set
#              (exclusive check-out, rotate on check-in)
#   static     a service account -> static role <tier prefix>/<sam>
#              (scheduled rotation; onboarding is gated on dependencies)
#
# Never collects `description` or any password-ish attribute: real ADs keep
# passwords in descriptions, and a discovery report must not copy them.
# The bind password arrives on stdin and goes to ldapsearch on a pipe
# (-y /dev/stdin): never in argv, never printed.
# =============================================================================
import argparse
import base64
import datetime as dt
import json
import os
import subprocess
import sys

IN_CHAIN = "1.2.840.113556.1.4.1941"   # LDAP_MATCHING_RULE_IN_CHAIN
UF_ACCOUNTDISABLE = 0x2
FILETIME_EPOCH_OFFSET = 11644473600   # seconds between 1601-01-01 and 1970-01-01
ATTRS = ["sAMAccountName", "userAccountControl", "adminCount", "servicePrincipalName",
         "lastLogonTimestamp", "pwdLastSet", "whenCreated", "primaryGroupID"]


def die(msg: str) -> None:
    print(f"discover.py: {msg}", file=sys.stderr)
    sys.exit(1)


def ldap_escape(value: str) -> str:
    # RFC 4515 filter escaping: a group CN or DN with ( ) * \ must not
    # change the meaning of the filter it is pasted into.
    out = []
    for ch in value:
        if ch in "*()\\\0":
            out.append("\\%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def parse_ldif(text: str):
    """Minimal LDIF reader: dn/attr values, base64 (attr::), continuation lines."""
    entries, cur = [], None
    lines = []
    for raw in text.splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]          # RFC 2849 continuation
        else:
            lines.append(raw)
    for line in lines + [""]:
        if not line.strip():
            if cur is not None and "dn" in cur:
                entries.append(cur)
            cur = None
            continue
        if line.startswith("#"):
            continue                       # comments, including # refldaps:// referrals
        if ":" not in line:
            continue
        key, _, rest = line.partition(":")
        if rest.startswith(":"):
            value = base64.b64decode(rest[1:].strip())
            if key.lower() != "objectsid":   # binary SID stays bytes (it may happen to be valid UTF-8)
                value = value.decode("utf-8", errors="replace")
        else:
            value = rest[1:] if rest.startswith(" ") else rest
        if cur is None:
            cur = {}
        cur.setdefault(key, []).append(value)
    return entries


class Ldap:
    def __init__(self, uri: str, bind_dn: str, password: str):
        self.uri, self.bind_dn, self.password = uri, bind_dn, password

    def search(self, base: str, flt: str, attrs, scope: str = "sub"):
        cmd = ["ldapsearch", "-LLL", "-x", "-o", "ldif-wrap=no",
               "-E", "pr=500/noprompt",          # paged: real ADs cap at 1000 per page
               "-H", self.uri, "-D", self.bind_dn, "-y", "/dev/stdin",
               "-s", scope, "-b", base, flt] + list(attrs)
        env = dict(os.environ, LDAPTLS_REQCERT="demand")
        proc = subprocess.run(cmd, input=self.password.encode(), capture_output=True, env=env)
        if proc.returncode == 32:              # noSuchObject: e.g. an OU the policy names is absent
            return []
        if proc.returncode != 0:
            err = proc.stderr.decode(errors="replace").strip().splitlines()
            reason = err[-1] if err else "no error text"
            if proc.returncode == 49:
                reason = "invalidCredentials (49) - check the discovery bind account/password"
            die(f"ldapsearch failed (exit {proc.returncode}) for base {base}: {reason}")
        return parse_ldif(proc.stdout.decode(errors="replace"))


def first(entry, key, default=None):
    vals = entry.get(key)
    return vals[0] if vals else default


def filetime_to_iso(value):
    try:
        ft = int(value)
    except (TypeError, ValueError):
        return None
    if ft <= 0 or ft >= 0x7FFFFFFFFFFFFFFF:
        return None
    ts = ft / 10_000_000 - FILETIME_EPOCH_OFFSET
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).replace(microsecond=0)


def generalized_to_dt(value):
    if not value:
        return None
    try:
        return dt.datetime.strptime(value.split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def iso(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def sid_rid(sid):
    # objectSid is binary; the RID is its last sub-authority (little-endian).
    if not isinstance(sid, (bytes, bytearray)) or len(sid) < 8:
        return None
    return int.from_bytes(sid[-4:], "little")


def dn_in(dn: str, ou_rdn: str, base: str) -> bool:
    # True if dn sits inside OU=<x>,<base> (any depth).
    return dn.lower().endswith(f"{ou_rdn},{base}".lower())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--uri", required=True, help="ldaps://dc01.corp.example")
    ap.add_argument("--base-dn", required=True)
    ap.add_argument("--bind-dn", required=True)
    ap.add_argument("--policy", default="/pam/pam-policy.json")
    ap.add_argument("--stale-days", type=int, help="override the policy's stale_days")
    args = ap.parse_args()

    password = sys.stdin.read().strip("\r\n")
    if not password:
        die("empty bind password on stdin")
    with open(args.policy, encoding="utf-8") as fh:
        policy = json.load(fh)
    stale_days = args.stale_days if args.stale_days is not None else int(policy["stale_days"])
    grace_days = int(policy.get("never_logged_on_grace_days", 30))
    tiers = policy["tiers"]
    tier_rank = {name: i for i, name in enumerate(tiers)}   # tier0 < tier1 < svc
    group_tier = {g["cn"].lower(): g["tier"] for g in policy["privileged_groups"]}
    exclusions = {k.lower(): v for k, v in policy.get("exclusions", {}).items()}
    base = args.base_dn
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

    ldap = Ldap(args.uri, args.bind_dn, password)
    password = ""

    # 1. The privileged groups that exist in THIS directory (Key Admins etc.
    #    only exist at newer functional levels), with their RIDs.
    gfilter = "(&(objectClass=group)(|" + "".join(f"(cn={ldap_escape(g['cn'])})" for g in policy["privileged_groups"]) + "))"
    groups = ldap.search(base, gfilter, ["cn", "objectSid"])
    if not groups:
        die("no privileged groups found - wrong base DN, or the bind account cannot read the directory")

    members = {}   # sam(lower) -> set of privileged group CNs (direct, nested or primary)
    for g in groups:
        cn, gdn = first(g, "cn"), first(g, "dn")
        for u in ldap.search(base, f"(&(objectCategory=person)(objectClass=user)(memberOf:{IN_CHAIN}:={ldap_escape(gdn)}))", ["sAMAccountName"]):
            members.setdefault(first(u, "sAMAccountName").lower(), set()).add(cn)
        rid = sid_rid(first(g, "objectSid"))
        if rid:
            for u in ldap.search(base, f"(&(objectCategory=person)(objectClass=user)(primaryGroupID={rid}))", ["sAMAccountName"]):
                members.setdefault(first(u, "sAMAccountName").lower(), set()).add(cn)

    # 2. Every candidate with its attributes: SPN or adminCount anywhere, plus
    #    everything in the policy's service / privileged OUs, plus the group
    #    members found above (merged by DN).
    found = {}
    for e in ldap.search(base, "(&(objectCategory=person)(objectClass=user)(|(servicePrincipalName=*)(adminCount=1)))", ATTRS):
        found[first(e, "dn").lower()] = e
    for ou in policy.get("service_account_ous", []) + policy.get("privileged_account_ous", []):
        for e in ldap.search(f"{ou},{base}", "(&(objectCategory=person)(objectClass=user))", ATTRS):
            found[first(e, "dn").lower()] = e
    if members:
        known = {first(e, "sAMAccountName", "").lower() for e in found.values()}
        missing = [s for s in members if s not in known]
        for i in range(0, len(missing), 50):      # keep each OR filter a sane size
            chunk = missing[i:i + 50]
            flt = "(&(objectCategory=person)(objectClass=user)(|" + "".join(f"(sAMAccountName={ldap_escape(s)})" for s in chunk) + "))"
            for e in ldap.search(base, flt, ATTRS):
                found[first(e, "dn").lower()] = e

    accounts = []
    for e in found.values():
        dn = first(e, "dn")
        sam = first(e, "sAMAccountName")
        if not sam:
            continue
        uac = int(first(e, "userAccountControl", "0") or 0)
        spns = e.get("servicePrincipalName", [])
        admin_count = first(e, "adminCount") == "1"
        last_logon = filetime_to_iso(first(e, "lastLogonTimestamp"))
        pwd_last_set = filetime_to_iso(first(e, "pwdLastSet"))
        created = generalized_to_dt(first(e, "whenCreated"))
        groups_of = sorted(members.get(sam.lower(), set()))
        tier_of_groups = sorted({group_tier[g.lower()] for g in groups_of}, key=lambda t: tier_rank.get(t, 99))
        is_service = bool(spns) or any(dn_in(dn, ou, base) for ou in policy.get("service_account_ous", []))
        tier = tier_of_groups[0] if tier_of_groups else ("svc" if is_service else None)

        # lastLogonTimestamp replicates lazily (~14 days), so it is the right
        # attribute for "stale" across DCs; lastLogon is per-DC and not used.
        # A never-used account gets a grace period from creation (a new admin
        # who has not signed in yet is not "stale"); after that it is.
        if last_logon:
            days = (now - last_logon).days
            stale = days >= stale_days
            stale_reason = f"last logon {days}d ago (>= {stale_days}d)" if stale else ""
        else:
            age = (now - created).days if created else None
            stale = age is not None and age >= grace_days
            stale_reason = f"never logged on, created {age}d ago (grace {grace_days}d)" if stale else ""

        action, target, reason = None, None, ""
        if sam.lower() in exclusions:
            action, reason = "exception", f"policy exclusion: {exclusions[sam.lower()]}"
        elif uac & UF_ACCOUNTDISABLE:
            action, reason = "exception", "disabled account: remove privileged rights or delete, do not vault"
        elif admin_count and not groups_of:
            action, reason = "exception", "orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance"
        elif groups_of and stale:
            action, reason = "exception", f"stale privileged account ({stale_reason}): disable, then remove from groups"
        elif tier == "tier0" and spns:
            action, reason = "exception", "Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting"
        elif tier is None:
            action, reason = "exception", "in a PAM OU but neither privileged nor a service account: review ownership"
        elif is_service:
            action, target = "static", f"{tiers[tier]['static_prefix']}/{sam}" if tiers.get(tier, {}).get("static_prefix") else None
            if not target:
                action, reason = "exception", f"tier {tier} has no static_prefix for service accounts"
        else:
            lib = tiers.get(tier, {}).get("library")
            action, target = ("library", lib) if lib else ("exception", None)
            if not lib:
                reason = f"tier {tier} has no library set for human accounts"

        accounts.append({
            "sam": sam,
            "dn": dn,
            "tier": tier,
            "type": "service" if is_service else "human",
            "enabled": not (uac & UF_ACCOUNTDISABLE),
            "privileged_groups": groups_of,
            "spn_count": len(spns),
            "admin_count": admin_count,
            "last_logon": iso(last_logon) or "never",
            "pwd_last_set": iso(pwd_last_set),
            "when_created": iso(created),
            "stale": bool(stale),
            "stale_reason": stale_reason,
            "proposed_action": action,
            "proposed_target": target,
            "reason": reason,
        })

    accounts.sort(key=lambda a: (tier_rank.get(a["tier"], 99), a["sam"].lower()))
    json.dump({
        "generated_at": iso(now),
        "source": args.uri,
        "base_dn": base,
        "policy_version": policy.get("version"),
        "stale_days": stale_days,
        "privileged_groups_present": sorted(first(g, "cn") for g in groups),
        "accounts": accounts,
    }, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
