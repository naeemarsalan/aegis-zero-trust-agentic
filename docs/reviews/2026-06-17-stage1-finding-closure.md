# Stage 1 finding-closure verification (2026-06-17)

Self-verification of the fixes for the two CRITICALs in
`2026-06-16-variant-b-gitops-stage1.md`. The security-reviewer agent was retried twice and hit
transient API 529s, so this is a main-loop verification; **a final security-reviewer pass should
run before the actual merge to `main`** (merge is separately gated on Stage 2 secrets + a healthy
control plane, so there is time).

## Finding A — SPIRE_TLS_INSECURE → JWKS-spoofing/SVID-forgery: **CLOSED**
- `cmd/server/main.go:202 buildSpireHTTPClient` — verified by reading the code:
  - case 1 `SpireTLSInsecure` → `InsecureSkipVerify` is reachable **only** on explicit
    `SPIRE_TLS_INSECURE=true` (default false).
  - case 2 `SPIRE_CA_FILE` → `RootCAs` from PEM; **fail-closed** (returns error on unreadable
    file or zero parsed certs — no silent fallback).
  - case 3 default → `RootCAs` from the in-pod SPIFFE X.509 bundle
    (`x509Source.GetX509SVID()` → `GetX509BundleForTrustDomain` → `X509Authorities`), TLS 1.2 min;
    **fail-closed** (returns error if the bundle can't be obtained).
- Call site `main.go:120-123`: a `buildSpireHTTPClient` error **aborts startup**
  (`return fmt.Errorf(...)`) — no degraded-but-allowed path.
- Overlay `deployment-patch.yaml`: `SPIRE_TLS_INSECURE` removed; default secure path used.
- Image rebuilt + pushed `ext-proc-delegation:grant-e2e-jit-tlsverify`
  (`sha256:0488968457c3a52a1592283d0e35ca0d07abb6068933806a2a337082e763d163`); overlay pinned by
  **digest**. `go build/vet/test` green (13 pkgs) incl. 5 new `main_test.go` cases.
- **Residual (runtime verification, not a code defect):** Go still checks the JWKS endpoint
  hostname against the served cert SAN. If the live `spire-oidc` passthrough cert's SAN does not
  include `spire-oidc.apps.anaeem.na-launch.com`, the default path will **fail-closed** (SPIRE
  verifier init warns + disables the sandbox path → calls deny; no forgery, no leak). Confirm the
  SAN on the live route when the cluster returns; if mismatched, mount the correct CA via
  `SPIRE_CA_FILE`. This is safe-by-default, just possibly inconvenient — must be checked before
  declaring the journey green.

## Finding B — sandbox identity from attacker-settable label: **PARTIALLY-CLOSED (adequate for PoC)**
- Dedicated `e2e-harness` SA (`automountServiceAccountToken: false`), `serviceAccountName` pinned
  on the pod, empty-rules Role/RoleBinding, and an Audit Kyverno `ClusterPolicy`
  (`require-e2e-harness-serviceaccount`) requiring agent-sandbox pods labelled
  `nvidia-ida/e2e-harness=true` to use SA `e2e-harness`.
- **Bar raised:** an attacker now needs `pods:create` in `agent-sandbox` **and** the ability to
  run under the `e2e-harness` SA **and** (once Kyverno is re-enabled) to pass the admission check.
- **Residual:** Kyverno is parked (policy is Audit + controllers scaled 0), so the SA-pin is not
  enforced at admission right now; the CSID still binds on a forgeable label. The effective
  control today is **RBAC on `pods:create` in `agent-sandbox`** (admin-only by default). Adequate
  for a single-tenant PoC namespace. Production: enforce the Kyverno policy + tie the uuid to a
  launcher-controlled non-mutable field.

## Overall: merge-ready for the PoC, with two pre-merge gates
1. Final security-reviewer confirmation (API was overloaded at authoring time).
2. Live SAN check on the `spire-oidc` route before declaring the journey green (Finding A residual).
