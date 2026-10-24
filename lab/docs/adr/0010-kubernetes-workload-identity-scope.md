# ADR 0010: Kubernetes workload identity scope (merged into ADR 0011)

- **Status:** Merged into [ADR 0011](0011-out-of-scope-global-secure-access-verified-id-ciem.md) (scope boundaries) on 2026-10-21. This file stays so existing references resolve.

The decision is unchanged: one workload, one secret, one exchange on a
throwaway kind cluster, with the AKS mapping written and never applied. It
now sits in ADR 0011 next to what the lab leaves out, under "Decision". The
technical detail is in `lab/k8s/README.md` §3.
