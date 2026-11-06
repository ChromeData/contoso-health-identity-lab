#!/usr/bin/env python3
"""Flag Kubernetes RBAC rules that let an identity take over the cluster.

WHY: the workload-identity segment (lab/k8s/README.md) removes every static
secret from the pod's path. That is only worth something if no service account
or person can simply give itself more power. A subject that can `escalate`,
`bind`, `impersonate`, read every Secret, create pods, or mint service-account
tokens can get any secret anyway. This linter reads Role / ClusterRole YAML or
JSON (manifests, or a `kubectl get ... -o json` export) and names those rules
before anything is applied.

Ported from the author's earlier Conjur-Kubernetes-KubiScan lab (the linter,
its canary and its fixture only; the Conjur and KubiScan halves were dropped:
this lab already has a Conjur stand-in in lab/pam and Vault on kind here).

EXIT CODES (the canary depends on these; a crash must never read as a finding):
  0  read at least one Role/ClusterRole, found nothing risky outside built-ins
  1  found risky rules on non-built-in roles
  2  could not do the job: missing file, unparseable input, a list it cannot
     read, or no Role/ClusterRole read at all. "Nothing found" from reading
     nothing is the most dangerous answer a security check can give.

Python's own sys.exit("message") and an uncaught exception both exit 1, which
is the "findings" code. The earlier lab used sys.exit("error: ...") for a
missing file, so a canary that counted exit 1 as a detection passed on a file
that did not exist. Every error path here exits 2 instead (tests pin it).

Run:  python3 lab/k8s/rbac-lint/rbac_lint.py lab/k8s/rbac-lint/fixtures/risky-rbac.yaml
      kubectl get clusterroles,roles -A -o json > rbac.json && python3 ... rbac.json
"""

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not a finding
    print("error: PyYAML is required (pip install pyyaml, or apt install python3-yaml)", file=sys.stderr)
    sys.exit(2)

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
RBAC_KINDS = ("Role", "ClusterRole")


class LintError(Exception):
    """Input the linter cannot read safely. Always exit 2, never a finding."""


def _has(rule, key, *values):
    """True if rule[key] holds any of values, or the wildcard "*".

    "*" in verbs means every verb and in resources every resource, so a rule
    with verbs ["*"] on secrets can read secrets. Kubernetes RBAC semantics:
    https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources
    """
    got = rule.get(key, []) or []
    return any(v in got for v in values) or "*" in got


def _verb_on(rule, verb, resources):
    """True if the rule grants `verb` in a way that matters.

    An explicit verb ("escalate", "bind", "impersonate") is flagged on ANY
    resource: it has no use outside its own resources, so seeing it at all is
    worth a look. The wildcard verb "*" is flagged only on the resources where
    that verb means something (or on resources "*").

    Why scoped: the earlier lab flagged every verbs ["*"] rule as escalate +
    bind + impersonate whatever the resource. On a real k3s v1.31.4 cluster
    that turned k3s-cloud-controller-manager's verbs ["*"] on nodes into three
    false "can grant itself arbitrary permissions" findings (2026-11-06,
    lab/k8s/rbac-lint/README.md). A report full of false alarms gets ignored,
    which hides the true ones.
    """
    verbs = rule.get("verbs", []) or []
    if verb in verbs:
        return True
    return "*" in verbs and _has(rule, "resources", *resources)


# Where each verb matters (Kubernetes docs, checked 2026-11-06):
#   escalate, bind: "the roles or clusterroles resource in the
#     rbac.authorization.k8s.io API group"
#     https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping
#   impersonate: users, groups, serviceaccounts, uids, userextras/<extra>
#     https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/
# Why each one is an escalation path:
#   https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks
RBAC_ROLE_RESOURCES = ("roles", "clusterroles")
IDENTITY_RESOURCES = ("users", "groups", "serviceaccounts", "uids")

# (id, reason, predicate over one policy rule).
DANGEROUS = [
    ("escalate", "can grant itself arbitrary permissions (escalate)",
     lambda r: _verb_on(r, "escalate", RBAC_ROLE_RESOURCES)),
    ("bind", "can bind any role to itself, including cluster-admin (bind)",
     lambda r: _verb_on(r, "bind", RBAC_ROLE_RESOURCES)),
    ("impersonate", "can act as any user/group/SA (impersonate)",
     lambda r: _verb_on(r, "impersonate", IDENTITY_RESOURCES)
     or ("*" in (r.get("verbs", []) or [])
         and any(str(x).startswith("userextras") for x in (r.get("resources", []) or [])))),
    ("secrets-read", "can read secrets",
     lambda r: _has(r, "resources", "secrets")
     and _has(r, "verbs", "get", "list", "watch")),
    ("pods-create", "can create pods (run a pod as a more powerful service account)",
     lambda r: _has(r, "resources", "pods")
     and _has(r, "verbs", "create")),
    ("wildcard-all", "wildcard verb on wildcard resource (cluster-admin-equivalent)",
     lambda r: _has(r, "verbs", "*") and _has(r, "resources", "*")),
    ("token-create", "can mint service-account tokens",
     lambda r: _has(r, "resources", "serviceaccounts/token")
     and _has(r, "verbs", "create")),
]
REASONS = {rid: reason for rid, reason, _ in DANGEROUS}


def analyze_rule(rule):
    """Return the ids of every danger a single policy rule triggers."""
    if not isinstance(rule, dict):
        raise LintError(f"a policy rule is not a mapping: {rule!r}")
    return [rid for rid, _reason, pred in DANGEROUS if pred(rule)]


def _list_item_kind(list_kind, item):
    """The kind of one item inside a List / <Kind>List wrapper.

    THE LIST-WRAPPER FIX. `kubectl get -o json` returns kind "List" and stamps
    kind on every item. The Kubernetes API itself (kubectl get --raw, curl,
    client libraries, many exporters) returns a TYPED list, kind
    "ClusterRoleList", whose items carry NO kind or apiVersion: the type is
    stated once, on the list. The earlier version recursed into each item,
    saw no kind, and skipped it, so a raw API export of a cluster full of
    wildcard roles came back "No risky RBAC found" (its own typed-list test
    passed only because the test wrote kind on each item by hand). So: an item
    with no kind inherits it from a typed list; an item with no kind in a
    generic List is an error, not a skip.
    """
    kind = item.get("kind")
    if kind:
        return kind
    if list_kind != "List" and list_kind.endswith("List"):
        return list_kind[: -len("List")]
    raise LintError(f"an item in a {list_kind} has no kind; cannot tell what it is")


def analyze_doc(doc, _inherited_kind=None, stats=None):
    """Return findings for one object, descending into List wrappers.

    stats (optional dict) counts the Role/ClusterRole objects actually read,
    so the caller can refuse to report "clean" after reading none.
    """
    if doc is None:
        return []  # an empty YAML document (a stray '---'), not an object
    if not isinstance(doc, dict):
        raise LintError(f"a document is not a mapping: {type(doc).__name__}")

    kind = _inherited_kind or doc.get("kind", "") or ""

    if kind.endswith("List"):
        items = doc.get("items")
        if not isinstance(items, list):
            # A list we cannot walk must not read as an empty, clean list.
            raise LintError(f"{kind} has no items array (got {type(items).__name__})")
        findings = []
        for item in items:
            if not isinstance(item, dict):
                raise LintError(f"an item in a {kind} is not a mapping")
            findings.extend(analyze_doc(item, _list_item_kind(kind, item), stats))
        return findings

    if kind not in RBAC_KINDS:
        return []

    if stats is not None:
        stats["rbac_objects"] = stats.get("rbac_objects", 0) + 1

    meta = doc.get("metadata", {}) or {}
    name = meta.get("name", "?")

    # Kubernetes labels every role it ships with kubernetes.io/bootstrapping:
    # rbac-defaults (cluster-admin, admin, edit, system:*). They really can
    # escalate; listing them on every run buries the planted ones. Classified,
    # not suppressed: still returned, still counted, not what the exit code is
    # about. https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
    labels = meta.get("labels", {}) or {}
    builtin = labels.get("kubernetes.io/bootstrapping") == "rbac-defaults"

    rules = doc.get("rules", []) or []
    if not isinstance(rules, list):
        raise LintError(f"{kind}/{name}: rules is not a list")

    findings = []
    for rule in rules:
        for rid in analyze_rule(rule):
            findings.append({
                "kind": kind,
                "name": name,
                "risk": rid,
                "reason": REASONS[rid],
                "builtin": builtin,
            })
    return findings


def analyze_text(text, stats=None):
    """Findings across a multi-document YAML (or JSON) string."""
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise LintError(f"cannot parse input: {exc}") from exc
    findings = []
    for doc in docs:
        findings.extend(analyze_doc(doc, stats=stats))
    return findings


def run(argv, out=sys.stdout, err=sys.stderr):
    """CLI body; returns the exit code instead of exiting (testable)."""
    paths = [a for a in argv if not a.startswith("-")]
    flags = [a for a in argv if a.startswith("-")]
    unknown = [f for f in flags if f != "--include-builtin"]
    if unknown or not paths:
        print("usage: rbac_lint.py [--include-builtin] <manifest.yaml|export.json> ...", file=err)
        return EXIT_ERROR
    show_builtin = "--include-builtin" in flags

    stats = {"rbac_objects": 0}
    total = []
    for path in paths:
        p = Path(path)
        if not p.is_file():
            print(f"error: {path} does not exist or is not a file", file=err)
            return EXIT_ERROR
        try:
            total.extend(analyze_text(p.read_text(encoding="utf-8-sig"), stats))
        except (LintError, UnicodeDecodeError, OSError) as exc:
            print(f"error: {path}: {exc}", file=err)
            return EXIT_ERROR

    if stats["rbac_objects"] == 0:
        print("error: read no Role or ClusterRole objects; refusing to call that clean", file=err)
        return EXIT_ERROR

    custom = [f for f in total if not f["builtin"]]
    builtin = [f for f in total if f["builtin"]]

    for f in custom:
        print(f"  [{f['risk']:14}] {f['kind']}/{f['name']}: {f['reason']}", file=out)
    if builtin:
        print(file=out)
        if show_builtin:
            print("  --- Kubernetes built-ins (kubernetes.io/bootstrapping: rbac-defaults) ---", file=out)
            for f in builtin:
                print(f"  [{f['risk']:14}] {f['kind']}/{f['name']}: {f['reason']}", file=out)
        else:
            print(f"  ({len(builtin)} finding(s) on Kubernetes built-in roles hidden, "
                  f"--include-builtin to show)", file=out)

    print(file=out)
    print(f"read {stats['rbac_objects']} Role/ClusterRole object(s)", file=out)
    if custom:
        print(f"{len(custom)} risky RBAC rule(s) found on non-built-in roles.", file=out)
        return EXIT_FINDINGS
    print("No risky RBAC found outside Kubernetes' own defaults.", file=out)
    return EXIT_CLEAN


def main():
    try:
        code = run(sys.argv[1:])
    except Exception as exc:  # noqa: BLE001 - any crash is "could not run", never "findings"
        print(f"error: linter crashed: {exc!r}", file=sys.stderr)
        code = EXIT_ERROR
    sys.exit(code)


if __name__ == "__main__":
    main()
