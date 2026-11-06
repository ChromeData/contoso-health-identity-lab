# RBAC linter: who could give themselves more power?

The workload-identity segment ([`../README.md`](../README.md)) takes every
static secret out of the pod's path. That only holds if nobody, person or
service account, can simply give themselves more power. Anyone who can
`escalate`, `bind` or `impersonate`, read every Secret, create pods, or mint
service-account tokens can get any secret anyway, perfect secrets handling or
not. [`rbac_lint.py`](rbac_lint.py) reads Role and ClusterRole YAML or JSON
(manifests, or an export from a cluster) and names those rules before
anything is applied.

> **Status: RAN · harness.** The unit tests (39) and the canary run on every
> pull request in `lab-tests.yml` (no cluster). On 2026-11-06 the linter
> also ran against a real, throwaway k3s v1.31.4 cluster in Docker on the
> lab Mac, with `fixtures/risky-rbac.yaml` applied: record
> [`lab/evidence/k8s-rbac-lint/20261106T071006Z/`](../../evidence/k8s-rbac-lint/20261106T071006Z/run.txt)
> (capture log L07). It has **not** run against the lab's kind cluster
> (`ci/pipeline.sh` does not call it) or against AKS.

## What it flags

| Risk | The rule that trips it | Why it beats good secrets handling |
|---|---|---|
| `escalate` | verb `escalate` (or `*` on roles / clusterroles) | grant yourself any permission |
| `bind` | verb `bind` (or `*` on roles / clusterroles) | bind cluster-admin to yourself |
| `impersonate` | verb `impersonate` (or `*` on users, groups, serviceaccounts, uids, userextras) | act as someone more powerful |
| `secrets-read` | get / list / watch on `secrets` | read the secrets directly |
| `pods-create` | create on `pods` | run a pod as a more powerful service account |
| `token-create` | create on `serviceaccounts/token` | mint a token for any service account |
| `wildcard-all` | `*` verbs on `*` resources | cluster-admin by another name |

Roles Kubernetes ships itself are counted but kept out of the exit code;
`--include-builtin` prints them. A role counts as built-in only if it has
the label `kubernetes.io/bootstrapping: rbac-defaults` **and** a name
Kubernetes uses for its defaults (`cluster-admin`, `admin`, `edit`, `view`,
or `system:...`). Anyone can add the label to a manifest, so a labelled role
with any other name is a normal finding, marked as claiming to be built-in.
A namespaced Role is printed as `Role/<namespace>/<name>`.

Exit codes: **0** clean, **1** risky rules found, **2** could not do the job
(missing file, unreadable input, or no Role/ClusterRole read at all).

```bash
python3 lab/k8s/rbac-lint/rbac_lint.py some-manifests.yaml
kubectl get clusterroles,roles -A -o json > rbac.json && python3 lab/k8s/rbac-lint/rbac_lint.py rbac.json
bash lab/k8s/rbac-lint/canary.sh                                  # the self-test
python3 -I -m unittest discover -s lab/k8s/rbac-lint/tests -v     # the unit tests
```

Needs Python 3 and PyYAML, nothing else.

## The canary: proof the check can still fail

A security check that has never been seen to fail proves nothing.
[`canary.sh`](canary.sh) runs the linter on its own deliberately dangerous
fixture, [`fixtures/risky-rbac.yaml`](fixtures/risky-rbac.yaml) (never
applied by anything in this repo), in all three shapes it meets: as written,
wrapped the way `kubectl -o json` returns it, and as the Kubernetes API
returns it. Each planted role must be found for its own risk every time, not just "some
findings", because one wildcard role alone trips every risk. It also runs the
linter on [`fixtures/clean-rbac.yaml`](fixtures/clean-rbac.yaml), the lab's
own two human roles copied from `lab/terraform/k8s/identity/main.tf` (a
test fails if the copy and the Terraform drift apart), which must come back
clean, and on a missing file, which must be "could not run",
never a detection.

## What was fixed while porting

The linter, canary and risky fixture come from the author's earlier
Conjur-Kubernetes-KubiScan lab. The Conjur and KubiScan halves of that lab
were left behind (this lab already has a Conjur stand-in in `lab/pam` and
Vault on kind here). Running the old linter on the k3s cluster above found
three faults, all fixed here and pinned by tests that fail against the old
code:

1. **The list-wrapper fix was only half done.** The earlier lab fixed the
   `kubectl -o json` "List" wrapper, but the Kubernetes API itself returns a
   typed list (`ClusterRoleList`) whose items carry no `kind`. The old linter
   skipped every item, and on a cluster with the planted roles applied it
   said `No risky RBAC found` and exited 0. Items now take their kind from a
   typed list; a kind-less item in a plain List, or a list with no items
   array, is an error.
2. **A crash looked like a finding.** The old linter exited 1 for a missing
   file or bad input, the same code as "findings", so the old canary counted
   a wrong path as a detection. Every failure to run is now exit 2, and
   reading no Role/ClusterRole at all is exit 2, not "clean".
3. **False alarms.** `verbs: ["*"]` on `nodes` was reported as escalate +
   bind + impersonate. A wildcard verb now counts only on the resources where
   that verb means something (Kubernetes docs, cited in the code). On the
   k3s cluster that removed 9 false findings and kept every planted one.

## What it does NOT catch

- **Creating a Deployment, Job, DaemonSet and so on also runs pods.** The
  linter only flags `pods` create. The lab's `app-deployer` role can create
  Deployments; the lab closes that path with the
  `clinical-apps-workload-identity` admission policy, not with RBAC
  ([`../README.md`](../README.md) section 3).
- **Bindings.** It reads roles, not RoleBindings, so it says what a role
  allows, not who holds it.
- **Aggregated ClusterRoles** get their rules from the cluster at run time;
  in a manifest their `rules` are empty.
- **API groups** are not checked: a custom resource named `secrets` in
  another group would be flagged too (a false alarm, never a miss).
