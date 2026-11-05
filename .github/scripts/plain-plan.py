#!/usr/bin/env python3
"""plain-plan.py - a plain-English summary of a Terraform plan.

Reads `terraform show -json <planfile>` and prints short Markdown for people
who do not read Terraform: one headline, then one bullet per change.

    terraform show -json tfplan > "$RUNNER_TEMP/plan.json"
    python3 plain-plan.py "$RUNNER_TEMP/plan.json"            # "What this change does: ..."
    python3 plain-plan.py --applied "$RUNNER_TEMP/plan.json"  # "Applied: ..." (past tense)

Used by .github/workflows/terraform-plan.yml (top of the PR comment and the
run's Summary page) and terraform-apply.yml (the "Applied:" Summary).

Rules it keeps:
  * Standard library only: runs on the runner's stock python3.
  * Prints no attribute VALUES except a thing's own name (display_name /
    name / title) and fixed on/off states, and never a name Terraform marks
    sensitive (*_sensitive / sensitive_values). The plan JSON itself holds
    every variable value in clear text, so callers keep it out of the logs,
    out of artifacts, and delete it after use.
  * Never crashes on a missing or odd field: a resource it cannot describe
    becomes a generic "setting" bullet with its Terraform address.
  * Exit 0 on success; 1 (message on stderr, nothing on stdout) only when the
    file is not a readable plan at all. The workflows treat that as "no
    summary" and keep going.
"""

import argparse
import json
import re
import sys

# -----------------------------------------------------------------------------
# Friendly nouns. type -> (noun, hint). The noun is what a non-technical reader
# sees; the hint is the product term, shown in brackets after the name.
# -----------------------------------------------------------------------------
NOUNS = {
    # Entra ID governance (access packages)
    "azuread_access_package": ("access package", None),
    "azuread_access_package_catalog": ("access catalog", None),
    "azuread_access_package_assignment_policy": ("access request policy", None),
    "azuread_access_package_resource_catalog_association": ("catalog group", None),
    "azuread_access_package_resource_package_association": ("app group link", None),
    # Entra ID directory
    "azuread_group": ("group", None),
    "azuread_group_member": ("group membership", None),
    "azuread_user": ("user account", None),
    "azuread_administrative_unit": ("admin boundary", "administrative unit"),
    "azuread_directory_role": ("admin role", None),
    "azuread_directory_role_assignment": ("admin role", None),
    "azuread_group_role_management_policy": ("just-in-time admin rule", "PIM"),
    "azuread_privileged_access_group_eligibility_schedule": ("just-in-time eligibility", "PIM"),
    # Entra ID sign-in rules
    "azuread_conditional_access_policy": ("sign-in rule", "Conditional Access"),
    "azuread_named_location": ("network location", "Conditional Access"),
    "azuread_authentication_strength_policy": ("MFA strength rule", "authentication strength"),
    "azuread_authentication_strength_policy_fido2_combination_configuration": ("passkey setting", "FIDO2"),
    # Entra ID apps
    "azuread_application": ("app registration", None),
    "azuread_application_from_template": ("app registration", "from the app gallery"),
    "azuread_application_identifier_uri": ("app identifier", "identifier URI"),
    "azuread_application_redirect_uris": ("app sign-in return address", "redirect URIs"),
    "azuread_application_owner": ("app owner", None),
    "azuread_application_pre_authorized": ("pre-approved app access", None),
    "azuread_application_federated_identity_credential": ("keyless login trust", "federated credential"),
    "azuread_application_password": ("app password", None),
    "azuread_service_principal": ("enterprise app", None),
    "azuread_service_principal_token_signing_certificate": ("SAML signing certificate", None),
    "azuread_claims_mapping_policy": ("sign-in token rule", "claims mapping"),
    "azuread_service_principal_claims_mapping_policy_assignment": ("sign-in token rule link", "claims mapping"),
    "azuread_app_role_assignment": ("app access", None),
    "azuread_synchronization_job": ("account sync job", "provisioning"),
    "azuread_synchronization_secret": ("account sync credentials", "provisioning"),
    # Azure permissions
    "azurerm_role_assignment": ("permission", "Azure RBAC"),
    "azurerm_pim_eligible_role_assignment": ("just-in-time permission", "PIM"),
    "azurerm_pim_active_role_assignment": ("time-limited permission", "PIM"),
    "azurerm_role_management_policy": ("just-in-time permission rule", "PIM"),
    "azurerm_user_assigned_identity": ("managed identity", None),
    # Sentinel and monitoring
    "azurerm_sentinel_alert_rule_scheduled": ("alarm rule", "Sentinel"),
    "azurerm_sentinel_alert_rule_nrt": ("alarm rule", "Sentinel"),
    "azurerm_sentinel_automation_rule": ("automatic response rule", "Sentinel"),
    "azurerm_sentinel_watchlist": ("watchlist", "Sentinel"),
    "azurerm_sentinel_watchlist_item": ("watchlist entry", "Sentinel"),
    "azurerm_sentinel_log_analytics_workspace_onboarding": ("Sentinel setup", None),
    "azurerm_sentinel_data_connector_microsoft_threat_protection": ("security data feed", "Sentinel connector"),
    "azurerm_monitor_scheduled_query_rules_alert_v2": ("alarm rule", "Azure Monitor"),
    "azurerm_monitor_action_group": ("alert contact list", "action group"),
    "azurerm_monitor_diagnostic_setting": ("log forwarding setting", None),
    "azurerm_monitor_aad_diagnostic_setting": ("sign-in log forwarding", "Entra diagnostics"),
    "azurerm_monitor_data_collection_rule": ("log collection rule", None),
    "azurerm_monitor_data_collection_rule_association": ("log collection link", None),
    "azurerm_monitor_data_collection_endpoint": ("log collection endpoint", None),
    "azurerm_log_analytics_workspace": ("log store", "Log Analytics"),
    "azurerm_log_analytics_workspace_table_custom_log": ("log table", "Log Analytics"),
    # Secrets and storage
    "azurerm_key_vault": ("key vault", None),
    "azurerm_key_vault_secret": ("stored secret", "Key Vault"),
    "azurerm_key_vault_key": ("stored key", "Key Vault"),
    "azurerm_storage_account": ("storage account", None),
    "azurerm_storage_container": ("storage folder", "blob container"),
    "azurerm_resource_group": ("Azure resource folder", "resource group"),
    # Network and machines
    "azurerm_virtual_network": ("private network", "VNet"),
    "azurerm_subnet": ("network segment", "subnet"),
    "azurerm_network_security_group": ("firewall rule set", "NSG"),
    "azurerm_subnet_network_security_group_association": ("firewall link", None),
    "azurerm_public_ip": ("public IP address", None),
    "azurerm_network_interface": ("network card", None),
    "azurerm_private_endpoint": ("private connection", "private endpoint"),
    "azurerm_private_dns_zone": ("private DNS zone", None),
    "azurerm_private_dns_zone_virtual_network_link": ("private DNS link", None),
    "azurerm_windows_virtual_machine": ("virtual machine", None),
    "azurerm_linux_virtual_machine": ("virtual machine", None),
    "azurerm_virtual_machine_extension": ("VM add-on", None),
    "azurerm_managed_disk": ("disk", None),
    "azurerm_virtual_machine_data_disk_attachment": ("disk link", None),
    "azurerm_dev_test_global_vm_shutdown_schedule": ("auto-shutdown schedule", None),
    # Other roots (not planned by this pipeline, named anyway)
    "aws_ssoadmin_permission_set": ("AWS permission set", None),
    "aws_ssoadmin_account_assignment": ("AWS account grant", None),
    "aws_ssoadmin_managed_policy_attachment": ("AWS policy link", None),
    "aws_iam_role": ("AWS role", None),
    "aws_iam_role_policy": ("AWS role policy", None),
    "aws_iam_openid_connect_provider": ("AWS keyless login trust", None),
    "okta_group": ("Okta group", None),
    "okta_group_rule": ("Okta group rule", None),
    "okta_app_bookmark": ("Okta app tile", None),
    "okta_app_group_assignment": ("Okta app grant", None),
    "okta_idp_oidc": ("Okta identity provider link", None),
    "okta_policy_rule_idp_discovery": ("Okta sign-in routing rule", None),
    "random_password": ("generated password", None),
    "terraform_data": ("internal step", None),
}

# Unknown types: still a "setting", with the platform when the prefix says it.
PREFIX_NOUNS = (
    ("azuread_", "Entra ID setting"),
    ("azurerm_", "Azure setting"),
    ("aws_", "AWS setting"),
    ("okta_", "Okta setting"),
    ("kubernetes_", "Kubernetes setting"),
    ("helm_", "Kubernetes setting"),
    ("vault_", "Vault setting"),
)

NAME_ATTRS = ("display_name", "name", "title")

# Attributes that point at the thing a nameless resource belongs to
# ("SAML signing certificate for AWS IAM Identity Center").
PARENT_ATTRS = (
    "application_id", "application_object_id", "service_principal_id",
    "service_principal_object_id", "access_package_id", "catalog_id",
    "key_vault_id", "storage_account_id", "virtual_machine_id",
    "target_resource_id", "workspace_id", "log_analytics_workspace_id",
    "network_security_group_id", "subnet_id", "group_object_id",
    "data_collection_rule_id", "policy_id", "watchlist_id",
)

# Changed-field labels for "updates its ...". Default: "its <field words>".
# Field names that ARE credentials: a hidden change to one is "a secret value".
SECRET_FIELD = re.compile(r"(password|secret|token|key|credential|certificate|connection_string|sas|value)", re.I)

FIELD_LABELS = {
    "display_name": "its name",
    "name": "its name",
    "title": "its name",
    "description": "its description",
    "members": "its members",
    "owners": "its owners",
    "conditions": "who it applies to",
    "grant_controls": "what it requires",
    "session_controls": "its session limits",
    "query": "its detection query",
    "query_frequency": "how often it runs",
    "query_period": "how far back it looks",
    "severity": "its severity",
    "tactics": "its attack categories",
    "techniques": "its attack techniques",
    "incident": "its incident settings",
    "incident_configuration": "its incident settings",
    "entity_mapping": "what it links alerts to",
    "tags": "its tags",
    "email_receiver": "who it emails",
    "ip": "its IP ranges",
    "ip_ranges": "its IP ranges",
    "network_acls": "its network firewall",
    "approval_settings": "its approval steps",
    "requestor_settings": "who can request it",
    "assignment_review_settings": "its access reviews",
    "duration_in_days": "how long access lasts",
    "expiration_date": "when access ends",
    "extension_enabled": "whether access can be extended",
    "required_resource_access": "its API permissions",
    "app_role": "its app roles",
    "web": "its web sign-in settings",
    "group_membership_claims": "its group claims",
    "end_date": "its end date",
    "subject": "its subject",
    "issuer": "its issuer",
    "audiences": "its audiences",
    "activation_rules": "its activation rules",
    "active_assignment_rules": "its active-assignment rules",
    "eligible_assignment_rules": "its eligible-assignment rules",
    "notification_rules": "who it notifies",
    "role_definition_name": "its role",
    "role_definition_id": "its role",
    "principal_id": "who it is for",
    "scope": "where it applies",
}

# Fields whose change is bookkeeping, not meaning.
NOISE_FIELDS = {"id", "object_id", "timeouts", "etag", "last_updated",
                "created_date_time", "modified_date_time"}

CA_STATE = {
    "enabled": "on",
    "disabled": "off",
    "enabledForReportingButNotEnforced": "report-only",
}

ACTION_ORDER = ("add", "change", "replace", "remove", "import", "forget")

# action -> (bullet verb present, past, headline verb present, past)
VERBS = {
    "add": ("Adds", "Added", "adds", "added"),
    "change": ("Changes", "Changed", "changes", "changed"),
    "replace": ("Replaces", "Replaced", "replaces", "replaced"),
    "remove": ("Removes", "Removed", "removes", "removed"),
    "import": ("Starts managing existing", "Started managing existing",
               "starts managing", "started managing"),
    "forget": ("Stops managing", "Stopped managing", "stops managing", "stopped managing"),
}

# Small verbs inside the details. key -> (present, past)
SMALL = {
    "adds": ("adds", "added"),
    "removes": ("removes", "removed"),
    "relinks": ("re-links", "re-linked"),
    "updates": ("updates", "updated"),
    "renames": ("renames it from", "renamed it from"),
    "on": ("turns it on", "turned it on"),
    "off": ("turns it off", "turned it off"),
    "report-only": ("sets it to report-only, so it logs but does not block",
                    "set it to report-only, so it logs but does not block"),
    "replace": ("removes it and creates a new one", "removed it and created a new one"),
    "import": ("starts managing it in code", "started managing it in code"),
    "deposed": ("an old leftover copy", "an old leftover copy"),
    "stays": ("it stays in place", "it stays in place"),
    "unchanged": ("no change to it", "no change to it"),
}

DEFAULT_MAX_ITEMS = 25
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------
def md(text, limit=100):
    """Escape text for inline Markdown on GitHub (no HTML, no @mentions)."""
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()
    if len(s) > limit:
        s = s[: limit - 3].rstrip() + "..."
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"([\\`*_\[\]|~])", r"\\\1", s)
    return s.replace("@", "&#64;")


def code(text, limit=140):
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).replace("`", "'").strip()
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return "`" + s + "`"


def plural(noun):
    if noun.endswith("y") and noun[-2:-1] not in "aeiou":
        return noun[:-1] + "ies"
    if noun.endswith(("s", "x", "ch", "sh")):
        return noun + "es"
    return noun + "s"


def join_and(parts):
    parts = [p for p in parts if p]
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def deep_true(v):
    """True if v is True or holds a True anywhere (sensitive / unknown maps)."""
    if v is True:
        return True
    if isinstance(v, dict):
        return any(deep_true(x) for x in v.values())
    if isinstance(v, list):
        return any(deep_true(x) for x in v)
    return False


def flag(marks, key):
    """Is `key` marked (sensitive or unknown) in a Terraform marks object?"""
    if marks is True:
        return True
    if isinstance(marks, dict):
        return deep_true(marks.get(key))
    return False


def as_dict(v):
    return v if isinstance(v, dict) else {}


def noun_for(rtype):
    if rtype in NOUNS:
        return NOUNS[rtype]
    for prefix, noun in PREFIX_NOUNS:
        if str(rtype).startswith(prefix):
            return (noun, None)
    return ("setting", None)


def safe_name(values, sens, unknown=None):
    """The thing's own name, unless missing, unknown or marked sensitive."""
    if not isinstance(values, dict) or sens is True:
        return None
    for attr in NAME_ATTRS:
        v = values.get(attr)
        if isinstance(v, str) and v.strip() and not flag(sens, attr) and not flag(unknown, attr):
            return v.strip()
    return None


def tail(s):
    return s.rstrip("/").rsplit("/", 1)[-1]


# -----------------------------------------------------------------------------
# Everything the plan knows about each address, for names and id lookups.
# -----------------------------------------------------------------------------
class Known:
    def __init__(self, plan):
        self.res = {}
        self._walk(as_dict(as_dict(plan.get("prior_state")).get("values")).get("root_module"), "before")
        self._walk(as_dict(plan.get("planned_values")).get("root_module"), "after")
        for rc in plan.get("resource_changes") or []:
            if not isinstance(rc, dict) or rc.get("deposed") or not rc.get("address"):
                continue
            ch = as_dict(rc.get("change"))
            info = self._info(rc)
            if isinstance(ch.get("before"), dict):
                info["before"], info["before_sens"] = ch["before"], ch.get("before_sensitive")
            if isinstance(ch.get("after"), dict):
                info["after"], info["after_sens"] = ch["after"], ch.get("after_sensitive")
                info["after_unknown"] = ch.get("after_unknown")
        self._index_ids()
        self.config = as_dict(as_dict(plan.get("configuration")).get("root_module"))

    def _info(self, r):
        addr = r["address"]
        info = self.res.setdefault(addr, {
            "address": addr, "type": r.get("type") or "", "mode": r.get("mode") or "managed",
            "index": r.get("index"), "module": r.get("module_address") or "",
            "before": None, "after": None, "before_sens": None, "after_sens": None,
            "after_unknown": None,
        })
        if not info["module"]:
            info["module"] = module_of(addr)
        return info

    def _walk(self, mod, side, depth=0):
        mod = as_dict(mod)
        if depth > 50:
            return
        for r in mod.get("resources") or []:
            if not isinstance(r, dict) or not r.get("address") or r.get("deposed_key"):
                continue
            info = self._info(r)
            if isinstance(r.get("values"), dict):
                info[side] = r["values"]
                info[side + "_sens"] = r.get("sensitive_values")
        for child in mod.get("child_modules") or []:
            self._walk(child, side, depth + 1)

    def _index_ids(self):
        self.exact, self.tails = {}, {}
        # Named, managed resources win an id clash (an association can share
        # its parent's id, e.g. a subnet's NSG link).
        ranked = sorted(self.res.values(), key=lambda i: (
            self.name(i["address"]) is None, i["mode"] != "managed", i["address"]))
        for info in ranked:
            keys = ["id", "object_id", "template_id"]
            if info["type"].endswith("_identity"):
                keys.append("principal_id")
            for vals in (info["before"], info["after"]):
                for k in keys:
                    v = as_dict(vals).get(k)
                    if isinstance(v, str) and v:
                        self.exact.setdefault(v, info["address"])
                        if "/" in v:
                            self.tails.setdefault(tail(v), info["address"])

    def name(self, addr):
        info = self.res.get(addr)
        if not info:
            return None
        return (safe_name(info["after"], info["after_sens"], info["after_unknown"])
                or safe_name(info["before"], info["before_sens"]))

    def value(self, addr, key):
        """A non-sensitive, known string attribute (ids only, never printed)."""
        info = self.res.get(addr) or {}
        for side in ("after", "before"):
            vals = info.get(side)
            sens = info.get(side + "_sens")
            unk = info.get("after_unknown") if side == "after" else None
            if isinstance(vals, dict) and not flag(sens, key) and not flag(unk, key):
                v = vals.get(key)
                if isinstance(v, str) and v:
                    return v
        return None

    def resolve(self, ref):
        """Address of the resource an id string points at, or None."""
        if not isinstance(ref, str) or not ref:
            return None
        if ref in self.exact:
            return self.exact[ref]
        if "/" in ref and tail(ref) in self.exact:
            return self.exact[tail(ref)]
        return self.tails.get(ref)

    def find(self, rtype, index=None, module=None, block=None):
        """The single managed address matching the filters, else None."""
        hits = [i["address"] for i in self.res.values()
                if i["mode"] == "managed" and i["type"] == rtype
                and (index is None or i["index"] == index)
                and (module is None or i["module"] == module)
                and (block is None or i["address"] == block or i["address"].startswith(block + "["))]
        return hits[0] if len(hits) == 1 else None

    def config_ref(self, module, rtype, rname, attr, target_type):
        """From the configuration: which `target_type` block does attr point at?"""
        mod = self.config
        for call in re.findall(r"module\.([^.\[]+)", module or ""):
            mod = as_dict(as_dict(as_dict(mod.get("module_calls")).get(call)).get("module"))
        for r in mod.get("resources") or []:
            if isinstance(r, dict) and r.get("address") == f"{rtype}.{rname}":
                refs = as_dict(as_dict(r.get("expressions")).get(attr)).get("references") or []
                for ref in refs:
                    m = re.match(r"^" + re.escape(target_type) + r"\.([A-Za-z0-9_-]+)", str(ref))
                    if m:
                        block = f"{target_type}.{m.group(1)}"
                        return f"{module}.{block}" if module else block
        return None


def module_of(address):
    """'module.a[0].module.b.azuread_group.x["k"]' -> 'module.a[0].module.b'."""
    parts = re.findall(r'module\.[^.\[]+(?:\[[^\]]*\])?', address)
    out = []
    rest = address
    for p in parts:
        if rest.startswith(p + "."):
            out.append(p)
            rest = rest[len(p) + 1:]
        else:
            break
    return ".".join(out)


# -----------------------------------------------------------------------------
# One bullet.
# -----------------------------------------------------------------------------
class Item:
    def __init__(self, action, rtype, address, phrase, pos):
        self.action = action
        self.type = rtype
        self.noun, self.hint = noun_for(rtype)
        self.address = address
        self.phrase = phrase          # Markdown: "**Name**" or "`address`"
        self.details = []             # list of callables tense -> str
        self.kids = {"add": [], "remove": [], "relink": []}  # (noun, label_md)
        self.pos = pos

    def has_child_removals(self):
        return bool(self.kids["remove"] or self.kids["relink"])

    def render(self, past):
        t = 1 if past else 0
        verb = VERBS[self.action][t]
        out = f"{verb} {self.noun} {self.phrase}"
        if self.hint:
            out += f" ({self.hint})"
        details = [d(t) for d in self.details]
        details = [d for d in details if d]
        if self.action in ("add", "replace") and self.kids["add"]:
            out += " with " + kid_list(self.kids["add"])
        elif self.action == "change":
            for key, verb_key in (("add", "adds"), ("remove", "removes"), ("relink", "relinks")):
                if self.kids[key]:
                    details.append(SMALL[verb_key][t] + " " + kid_list(self.kids[key]))
        if details:
            out += ": " + "; ".join(details)
        return out


def kid_list(kids):
    """[('app group','A'),('app group','B')] -> 'app groups A and B'."""
    by_noun = {}
    for noun, label in kids:
        by_noun.setdefault(noun, []).append(label)
    parts = []
    for noun, labels in by_noun.items():
        shown = labels[:5]
        more = len(labels) - len(shown)
        if more:
            shown.append(f"{more} more")
        parts.append((noun if len(labels) == 1 else plural(noun)) + " " + join_and(shown))
    return join_and(parts)


def action_of(change):
    acts = change.get("actions") or []
    if not isinstance(acts, list):
        return None
    if "create" in acts and ("delete" in acts or "forget" in acts):
        return "replace"
    if "create" in acts:
        return "add"
    if "delete" in acts:
        return "remove"
    if "update" in acts:
        return "change"
    if "forget" in acts:
        return "forget"
    if change.get("importing") and ("no-op" in acts or not acts):
        return "import"
    return None  # no-op, read


# -----------------------------------------------------------------------------
# Phrases: how a resource is named in its bullet.
# -----------------------------------------------------------------------------
def principal_label(known, values, sens, id_key, name_key):
    if isinstance(values.get(name_key), str) and values[name_key] and not flag(sens, name_key):
        return values[name_key]
    addr = known.resolve(values.get(id_key)) if not flag(sens, id_key) else None
    return known.name(addr) if addr else None


def scope_label(known, scope):
    if not isinstance(scope, str) or not scope:
        return None
    addr = known.resolve(scope)
    if addr and known.name(addr):
        return known.name(addr)
    s = scope.rstrip("/")
    if s == "":
        return "the whole tenant"
    if re.match(r"^/subscriptions/[^/]+$", s, re.I):
        return "the whole subscription"
    last = tail(s)
    return None if GUID.match(last) else last


def phrase_for(known, rc, values, sens, unknown):
    rtype = rc.get("type") or ""
    address = rc.get("address") or "?"
    if values is None or sens is True:
        return code(address)

    if rtype == "azurerm_role_assignment" or rtype.startswith("azurerm_pim_"):
        role = values.get("role_definition_name")
        role = role if isinstance(role, str) and role and not flag(sens, "role_definition_name") else None
        who = principal_label(known, values, sens, "principal_id", "principal_display_name")
        where = None if flag(sens, "scope") else scope_label(known, values.get("scope"))
        bits = []
        if role:
            bits.append(f"**{md(role)}**")
        if who:
            bits.append(f"for **{md(who)}**")
        if where:
            bits.append(f"on **{md(where)}**")
        return " ".join(bits) if bits else code(address)

    if rtype == "azuread_app_role_assignment":
        who = principal_label(known, values, sens, "principal_object_id", "principal_display_name")
        app = principal_label(known, values, sens, "resource_object_id", "resource_display_name")
        if who or app:
            return " ".join(x for x in (who and f"for **{md(who)}**", app and f"to **{md(app)}**") if x)
        return code(address)

    if rtype == "azuread_directory_role_assignment":
        role_addr = known.resolve(values.get("role_id"))
        role = known.name(role_addr) if role_addr else None
        who = principal_label(known, values, sens, "principal_object_id", "principal_display_name")
        bits = [f"**{md(role)}**" if role else "", f"for **{md(who)}**" if who else ""]
        bits = [b for b in bits if b]
        return " ".join(bits) if bits else code(address)

    own = safe_name(values, sens, unknown)
    if own:
        return f"**{md(own)}**"
    for attr in PARENT_ATTRS:
        if flag(sens, attr):
            continue
        parent = known.resolve(values.get(attr))
        if parent and parent != address and known.name(parent):
            return f"for **{md(known.name(parent))}**"
    return code(address)


# -----------------------------------------------------------------------------
# Details: what changed inside an update or a replace.
# -----------------------------------------------------------------------------
def field_label(key):
    return FIELD_LABELS.get(key, "its " + str(key).replace("_", " "))


def update_details(rc, change):
    before, after = as_dict(change.get("before")), as_dict(change.get("after"))
    bsens, asens = change.get("before_sensitive"), change.get("after_sensitive")
    unknown = change.get("after_unknown")
    rtype = rc.get("type") or ""
    details, changed, secret, hidden = [], [], 0, []
    keys = sorted(set(before) | set(after) | set(as_dict(unknown)))
    for k in keys:
        if k in NOISE_FIELDS:
            continue
        if before.get(k) == after.get(k) and not flag(unknown, k):
            continue
        if bsens is True or asens is True or flag(bsens, k) or flag(asens, k):
            # Terraform hides the VALUE, not the setting's name. Only a field
            # that is itself a credential is called a secret; owners or an
            # email list hidden because they came from a sensitive variable
            # are named, so a viewer is not told a secret changed when it
            # was who owns the app.
            if SECRET_FIELD.search(str(k)):
                secret += 1
            else:
                hidden.append(k)
            continue
        changed.append(k)

    if "state" in changed and rtype == "azuread_conditional_access_policy":
        old, new = before.get("state"), after.get("state")
        if old in CA_STATE and new in CA_STATE:
            changed.remove("state")
            was = CA_STATE[old] + (", which logs but does not block" if CA_STATE[old] == "report-only" else "")
            details.append(lambda t, key=CA_STATE[new], was=was: f"{SMALL[key][t]} (it was {was})")
    if "enabled" in changed and isinstance(before.get("enabled"), bool) and isinstance(after.get("enabled"), bool):
        changed.remove("enabled")
        key = "on" if after["enabled"] else "off"
        details.append(lambda t, key=key: SMALL[key][t])
    for attr in NAME_ATTRS:
        if attr in changed:
            old = before.get(attr)
            if isinstance(old, str) and old.strip() and not flag(unknown, attr):
                changed.remove(attr)
                details.append(lambda t, old=old: f"{SMALL['renames'][t]} {md(old)}")
            break
    if changed:
        labels = [field_label(k) for k in changed[:3]]
        more = len(changed) - len(labels)
        if more:
            labels.append(f"{more} other setting" + ("s" if more > 1 else ""))
        details.append(lambda t, labels=labels: f"{SMALL['updates'][t]} {join_and(labels)}")
    if hidden:
        labels = [field_label(k) for k in hidden[:3]]
        more = len(hidden) - len(labels)
        if more:
            labels.append(f"{more} other setting" + ("s" if more > 1 else ""))
        tail = " (value hidden)" if len(labels) == 1 else " (values hidden)"
        details.append(lambda t, labels=labels, tail=tail: f"{SMALL['updates'][t]} {join_and(labels)}{tail}")
    if secret:
        details.append(lambda t, n=secret: f"{SMALL['updates'][t]} "
                       + ("a secret value" if n == 1 else f"{n} secret values") + " (not shown)")
    return details


REPLACE_REASONS = {
    "replace_because_tainted": "because it was marked as damaged",
    "replace_by_request": "because a fresh copy was requested",
    "replace_by_triggers": "because something it depends on changed",
}


def replace_detail(rc, change):
    keys = []
    sens = (change.get("before_sensitive"), change.get("after_sensitive"))
    for path in change.get("replace_paths") or []:
        if isinstance(path, list) and path and isinstance(path[0], str):
            k = path[0]
            label = "a secret value" if any(flag(s, k) for s in sens) else field_label(k)
            if label not in keys:
                keys.append(label)
    reason = REPLACE_REASONS.get(rc.get("action_reason"))

    def render(t):
        base = SMALL["replace"][t]
        if keys:
            shown = keys[:3]
            if t:
                verb = "changed"
            else:
                verb = "changes" if len(shown) == 1 else "change"
            return f"{base}, because {join_and(shown)} {verb}"
        if reason:
            return f"{base}, {reason}"
        return base
    return render


# -----------------------------------------------------------------------------
# Child links folded into their parent ("Changes access package X: removes
# app group Y" instead of "Removes app group link `module...`").
# -----------------------------------------------------------------------------
FOLDS = {
    # child type: (parent attr, parent type, child noun, child-id attr)
    "azuread_access_package_resource_package_association":
        ("access_package_id", "azuread_access_package", "app group", "catalog_resource_association_id"),
    "azuread_access_package_resource_catalog_association":
        ("catalog_id", "azuread_access_package_catalog", "group", "resource_origin_id"),
}


def fold_target(known, rc, values):
    """(parent address, child label Markdown) for a foldable link, or None."""
    rtype = rc.get("type")
    parent_attr, parent_type, child_noun, child_attr = FOLDS[rtype]
    module = rc.get("module_address") or module_of(rc.get("address", ""))
    key = rc.get("index")
    pkey, gkey = None, None
    if rtype == "azuread_access_package_resource_package_association" and isinstance(key, str) and "." in key:
        pkey, gkey = key.split(".", 1)
    elif isinstance(key, str):
        gkey = key

    # Parent: by id, else by the configuration reference + the instance key.
    parent = known.resolve(values.get(parent_attr))
    if parent and known.res.get(parent, {}).get("type") != parent_type:
        parent = None
    if not parent:
        block = known.config_ref(module, rtype, rc.get("name"), parent_attr, parent_type)
        if block:
            parent = (known.find(parent_type, block=block)
                      or (pkey is not None and known.find(parent_type, index=pkey, block=block)) or None)
        if not parent:
            parent = known.find(parent_type, module=module, index=pkey) if pkey else known.find(parent_type, module=module)
    if not parent:
        return None

    # Child: the group's name.
    group = None
    ref = values.get(child_attr)
    hit = known.resolve(ref)
    if hit and known.res.get(hit, {}).get("type") == "azuread_access_package_resource_catalog_association":
        hit = known.resolve(known.value(hit, "resource_origin_id"))
    if hit and known.res.get(hit, {}).get("type") == "azuread_group":
        group = known.name(hit)
    if not group and rtype == "azuread_access_package_resource_package_association" and gkey:
        block = known.config_ref(module, rtype, rc.get("name"), child_attr,
                                 "azuread_access_package_resource_catalog_association")
        assoc = known.find("azuread_access_package_resource_catalog_association", index=gkey, block=block) if block else None
        hit = known.resolve(known.value(assoc, "resource_origin_id")) if assoc else None
        if hit:
            group = known.name(hit)
    if not group and gkey:
        hit = known.find("azuread_group", index=gkey)
        group = known.name(hit) if hit else None
    label = md(group) if group else (code(gkey) if gkey else code(rc.get("address", "?")))
    return parent, (child_noun, label)


# -----------------------------------------------------------------------------
# The summary.
# -----------------------------------------------------------------------------
def build_items(plan):
    known = Known(plan)
    items, by_addr = [], {}
    folds = []
    for pos, rc in enumerate(plan.get("resource_changes") or []):
        if not isinstance(rc, dict) or rc.get("mode") == "data":
            continue
        change = as_dict(rc.get("change"))
        action = action_of(change)
        if not action:
            continue
        address = rc.get("address") or "?"
        try:
            use_before = action in ("remove", "forget")
            values = change.get("before") if use_before else change.get("after")
            sens = change.get("before_sensitive") if use_before else change.get("after_sensitive")
            unknown = None if use_before else change.get("after_unknown")
            if not isinstance(values, dict):
                values, sens, unknown = change.get("before"), change.get("before_sensitive"), None
            values = values if isinstance(values, dict) else None

            if rc.get("type") in FOLDS and values is not None and action in ("add", "remove", "replace") \
                    and not rc.get("deposed"):
                target = fold_target(known, rc, values)
                if target:
                    folds.append((pos, action, target))
                    continue

            phrase = phrase_for(known, rc, values, sens, unknown)
            if phrase.startswith("`") and action in ("change", "replace", "import") \
                    and isinstance(change.get("before"), dict):
                # New name not known until apply: name it by its current one.
                phrase = phrase_for(known, rc, change["before"], change.get("before_sensitive"), None)
            item = Item(action, rc.get("type") or "", address, phrase, pos)
            if action == "change":
                item.details = update_details(rc, change)
                if change.get("importing"):
                    item.details.insert(0, lambda t: SMALL["import"][t])
            elif action == "replace":
                item.details = [replace_detail(rc, change)]
            elif action == "remove" and rc.get("deposed"):
                item.details = [lambda t: SMALL["deposed"][t]]
            elif action == "import":
                item.details = [lambda t: SMALL["unchanged"][t]]
            elif action == "forget":
                item.details = [lambda t: SMALL["stays"][t]]
        except Exception:  # never let one odd resource sink the summary
            item = Item(action, "", address, code(address), pos)
            item.noun, item.hint = "setting", None
        items.append(item)
        if not rc.get("deposed"):
            by_addr.setdefault(address, item)

    for pos, action, (parent, kid) in folds:
        item = by_addr.get(parent)
        if item is None:
            info = known.res.get(parent, {})
            name = known.name(parent)
            item = Item("change", info.get("type") or "", parent,
                        f"**{md(name)}**" if name else code(parent), pos)
            items.append(item)
            by_addr[parent] = item
        if item.action == "remove":
            continue  # removing the package removes its links too
        if action == "replace":
            item.kids["relink"].append(kid)
        else:
            item.kids[action].append(kid)
    items.sort(key=lambda i: (ACTION_ORDER.index(i.action), i.pos))
    return items


def headline(items, past):
    t = 1 if past else 0
    if not items:
        if past:
            return "**Applied:** nothing needed to change. The live lab already matched the code."
        return "**What this change does:** no changes to the live lab. It already matches the code."
    clauses, prev = [], None
    for act in ACTION_ORDER:
        group = [i for i in items if i.action == act]
        if not group:
            continue
        nouns = {i.noun for i in group}
        noun = nouns.pop() if len(nouns) == 1 else "thing"
        n = len(group)
        verb = VERBS[act][2 + t]
        word = noun if n == 1 else plural(noun)
        if act == "import":
            word = "existing " + word
        if noun == prev and act != "import":
            # Same kind of thing as the clause before: say "existing one(s)"
            # rather than a bare number ("adds 1 access package and changes 1."
            # read as unfinished on screen).
            clauses.append(f"{verb} {n} existing {'one' if n == 1 else 'ones'}")
        else:
            clauses.append(f"{verb} {n} {word}")
        prev = noun
    lead = "**Applied:**" if past else "**What this change does:**"
    text = f"{lead} {join_and(clauses)}."
    removes = any(i.action in ("remove", "replace") or i.has_child_removals() for i in items)
    if not removes:
        text += " Nothing was removed." if past else " Nothing is removed."
    return text


def summarize(plan, past=False, max_items=DEFAULT_MAX_ITEMS):
    if not isinstance(plan, dict):
        raise ValueError("not a Terraform JSON plan (expected an object)")
    items = build_items(plan)
    lines = [headline(items, past)]
    if items:
        lines.append("")
        for item in items[:max_items]:
            lines.append("- " + item.render(past))
        hidden = len(items) - max_items
        if hidden > 0:
            lines.append(f"- ...and {hidden} more (listed in the technical plan)")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Plain-English Markdown summary of `terraform show -json` output.")
    ap.add_argument("plan_json", help="path to the JSON plan, or - for stdin")
    ap.add_argument("--applied", action="store_true", help='past tense, headed "Applied:"')
    ap.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS, help="bullets to show (default 25)")
    args = ap.parse_args(argv)
    try:
        if args.plan_json == "-":
            plan = json.load(sys.stdin)
        else:
            with open(args.plan_json, encoding="utf-8") as fh:
                plan = json.load(fh)
        out = summarize(plan, past=args.applied, max_items=max(1, args.max_items))
    except (OSError, ValueError) as exc:  # json.JSONDecodeError is a ValueError
        print(f"plain-plan: cannot read a Terraform JSON plan: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
