# Research — Short-lived, operation-shaped JIT capability TTLs (prior art + recommendation)

**Date:** 2026-06-20
**Status:** Complete — design agreed; see `docs/adr/0014-operation-shaped-jit-ttl-decouple.md`
**Drives:** ADR-0014 (operation-shaped JIT TTL decouple)
**Method:** deep-research workflow (run `wf_b26c0416-4f8`): 5 search angles → 17 sources fetched → 80 claims → 25 adversarially verified (3-vote, 2/3 to kill) → 24 confirmed, 1 killed. Plus first-party reads of this repo + live cluster.

> For a master agent picking this up: the decision is settled (see **Decision** below). The rest is the cited evidence and the implementation touch-points. The actionable next step is implementing ADR-0014.

---

## TL;DR

We wanted operation-shaped JIT TTLs — one-shot writes (scale a Deployment) ~5 min/single-use, interactive `pods_exec` ~30 min — but jit-approver floors `duration_minutes` at 10. **Root cause:** the capability TTL and the Kubernetes SA-token TTL are coupled to one value, and Kubernetes TokenRequest hard-rejects SA tokens shorter than 600s. **Fix (industry-universal):** decouple a short-lived, issuer-controlled *capability* token (the gate-checked RS256 session JWT) from the longer-lived *actuation* credential (the SA token). The JWT can be any duration — 5 min, or single-use via `jti` consume-on-use. Our gate already authorizes only on the JWT, so we are one small change away.

---

## Decision (agreed 2026-06-19/20)

1. **Per-operation capability TTL drives ONLY the session-JWT `exp`.** SA-token mint clamped to `max(10min, ttl)` to satisfy the k8s floor; JWT validation floor relaxed to `ge=1`; `expires_at` returned to the agent = the JWT exp.
2. **Operation-shaped table** (derived server-side from `tool_scope`, not client-supplied):
   - one-shot mutating writes (`resources_scale`, `resources_create_or_update`, `create_firewall_rule_advanced`, `add_firewall_rule`) → **5-min JWT + single-use**
   - interactive (`pods_exec`, `pods_run`) → **30-min JWT + reuse-window**
3. **`jti` consume-on-use** for the single-use class: jit-gate does an atomic `INSERT INTO consumed_jti (jti, tool, …) ON CONFLICT DO NOTHING`; `rowcount==0` ⇒ replay ⇒ deny. **CNPG-backed from the start** (multi-replica safe), reusing the mint-gate L0/L1 CNPG pattern.
4. SA token remains a coarse outer backstop; safe because jit-gate is the sole NetworkPolicy-enforced ingress to the edit upstream.

---

## The Kubernetes fact (verified, high confidence)

Kubernetes TokenRequest **HARD-REJECTS** `expirationSeconds < 600` — a validation error (`MinTokenAgeSec = 600` in `pkg/apis/authentication/validation/validation.go`, PR #63999), **not** a silent clamp-up. Clamp-with-warning applies only on the **max** side (`--service-account-max-token-expiration`). The "extend to ~1 year" sentinel (`--service-account-extend-token-expiration`, 3607s) fires **only when the audience == kube-apiserver's own audience** — our Vault-issued SA token uses a non-apiserver audience, so it faces **only the 600s floor** (no silent 1-year surprise).

The floor is **industry-universal**, not a k8s bug:
- AWS STS `AssumeRole` hard-rejects sub-900s (15-min) sessions.
- Microsoft Entra PIM activation is hour-granular (1–24h).
- k8s SA tokens **cannot be individually revoked** (no central record) — so single-use **must** be implemented one layer up, at the capability/gate.

---

## The canonical pattern (verified, high confidence)

**Decouple a short-lived, issuer-controlled CAPABILITY token (gate-enforced exp) from the longer-lived ACTUATION credential.** The capability can be far shorter than any actuation-credential floor:

| System | Capability token | Note |
|---|---|---|
| **Teleport / SPIFFE** | 5-minute (300s) JWT-SVIDs by default | Signed by the Workload Identity CA; no relationship to any k8s SA token. |
| **Red Hat agentic zero-trust** (next.redhat.com, 2026-06-10) | X.509-SVID ("who") at transport + short JWT ("on behalf of whom") at app, via Envoy ext-proc | **Literally our SVID + RS256 session-JWT split.** |
| **Macaroons** | seconds-scale time caveats, checked per-request by the target | Decoupling of a gate-checked capability from upstream identity "without the target having any direct relationship with the issuer." |
| **DPoP (RFC 9449)** | short freshness window + `jti` single-use replay tracking | "A single-use check provides a very strong protection against replay." |
| **SuperTokens / OWASP LLM Top 10** | per-operation capability tokens 60–300s | Authz enforced at the tool server/sidecar, **never in the prompt**; RFC 8693 narrow-only. |

**True one-shot ≠ short TTL.** A 5-minute *reuse* window still permits N writes. For one-shot writes the correct property is `jti` consume-on-use (the DPoP model); the TTL is just a backstop. For interactive sessions, reuse-within-window is correct.

---

## First-party findings (this repo + live cluster)

- **The gate authorizes only on the JWT.** `gate.py:_check_capability()` decodes with `require:['exp']` + checks `tool_scope`; the SA-token lifetime is invisible to the authz decision.
- **The SA token is vestigial on this path.** `mcp-call` only ever reads `session_jwt` and sends `X-JIT-Session-JWT`; it never uses `sa_token`. Both the OpenShift and pfSense flows are JWT-gated.
- **The two TTLs are coupled by artifact, not policy.** `vault.py:issue_credentials` drives both the SA-token ttl (`~175,189-211`) and the JWT exp (`signing.py:300`) from `req.duration_minutes`; `models.py:86` floors it `ge=10`, yet the docstring says "1..60".
- **The `jti` is already there.** `signing.py:305` sets `jti = session_id` — ready for consume-on-use.
- **The security precondition holds and is gitops-durable.** `k8s-mcp-edit`'s sole ingress is `jit-gate-k8s` via NetworkPolicy `allow-ingress-edit-from-gate` (`services/jit-gate/deploy/jit-gate-k8s.yaml`; verified live: ingress `from app=jit-gate-k8s` only). Namespace default-deny is Kyverno-auto-injected. So a longer-lived-but-unused SA token is **not** a standing-privilege hole.
- **CNPG plumbing already exists.** The mint-gate L0/L1 work (`feat/jit-mint-gate-L0-L1`, `platform/jit-approver-db/`, shared `mint_core`, CNPG WORM) gives a connection/migration pattern to reuse for `consumed_jti`.

---

## Caveats / residual risks (carry into implementation)

1. **Reuse-window is a deliberate weakness, not a safe default.** One-shot writes belong in the single-use bucket → add `jti` consume-on-use, don't rely on a short TTL alone.
2. **SA token can outlive its authorization** by up to `max(10min, ttl) − ttl`. Acceptable **only** because the gate is the sole ingress to the edit upstream and nothing on this path reads the SA token. Optionally clamp the SA lease to the 10-min floor so the reaper revokes promptly.
3. **k8s SA tokens can't be individually revoked** — a consumed-but-unexpired capability still leaves a live-but-gate-unusable SA token until lease/reaper expiry.
4. **Multi-replica single-use** requires shared state — hence CNPG, not an in-process set (RFC 9449 multi-server caveat).
5. **Vendor-blog numbers** (SuperTokens 60–300s) are medium-confidence on the *specific* figures; the *pattern* is RFC/OWASP-corroborated.
6. **Time-sensitivity:** k8s behavior verified against v1.32–1.34 docs/source (current 2026-06); STS/Entra/Teleport/Vault floors current mid-2026.

---

## Open questions → resolved

| Question | Resolution |
|---|---|
| Operation-class → (ttl, single-use) table? | write = 5-min + single-use; exec = 30-min + reuse-window. |
| jti store: in-process vs shared? | **CNPG-backed from the start** (multi-replica safe). |
| Clamp SA lease to floor, or allow longer for exec? | Clamp SA mint to `max(10min, ttl)`; keep SA as backstop only. |
| Separate `capability_ttl` vs single `duration` internally clamped? | JWT exp driven by per-op capability TTL (`ge=1`); SA mint clamped to ≥600s. |

---

## Implementation touch-points (see ADR-0014 for detail)

| File | Change |
|---|---|
| `services/jit-approver/src/jit_approver/signing.py` | `operation_class_for(tool_scope)`; set JWT `exp` per class |
| `services/jit-approver/src/jit_approver/vault.py` | clamp SA-token ttl to `max(600s, capability_ttl)`; `expires_at` = JWT exp |
| `services/jit-approver/src/jit_approver/models.py` | relax JWT-duration floor to `ge=1`; keep SA-floor clamp |
| `services/jit-gate/gate.py` | single-use: atomic `consumed_jti` INSERT, deny on rowcount 0 |
| `services/agent-sandbox/agent-harness/bin/mcp-call` | none (already JWT-only) |
| `platform/jit-approver-db/` | migration: `consumed_jti(jti PK, tool, consumed_at)` |
| jit-gate NetworkPolicy + deployment | egress to CNPG + `DATABASE_URL` secretKeyRef |

**Before merge:** security-review pass (consume-on-use path, NetworkPolicy change, CNPG credential injection), then re-run `hack/test-openshift-jit.sh`.

---

## Sources

**Primary**
- KEP-1205 Bound Service Account Tokens — https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/1205-bound-service-account-tokens/README.md
- Kubernetes CSI TokenRequest (600s floor) — https://kubernetes-csi.github.io/docs/token-requests.html
- Kubernetes service-accounts admin reference — https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
- AWS STS AssumeRole (900s floor) — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- RFC 9449 DPoP §11.1 (single-use) — https://www.rfc-editor.org/rfc/rfc9449.html
- Teleport JWT-SVIDs (5-min default) — https://goteleport.com/docs/machine-workload-identity/workload-identity/jwt-svids/
- Red Hat agentic zero-trust (SVID + short JWT) — https://next.redhat.com/2026/06/10/wiring-zero-trust-identity-for-ai-agents-spiffe-token-exchange-and-kagenti/
- Macaroons (Stanford) — https://theory.stanford.edu/~ataly/Papers/macaroons.pdf
- HashiCorp Vault Kubernetes secrets engine — https://developer.hashicorp.com/vault/docs/secrets/kubernetes
- Microsoft Entra PIM settings — https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings

**Secondary / blog**
- SuperTokens — auth for AI agents — https://supertokens.com/blog/auth-for-ai-agents
- Teleport — OWASP Top 10 for agentic apps — https://goteleport.com/blog/owasp-top-10-agentic-applications/
- HashiCorp — agentic runtime security — https://www.hashicorp.com/en/blog/agentic-runtime-security-solving-agentic-ai-identity-and-access-gaps
- Neil Madden — macaroon access tokens / transactional auth — https://neilmadden.blog/2020/09/09/macaroon-access-tokens-for-oauth-part-2-transactional-auth/

**One claim killed (1-2 vote):** "kube-apiserver requires the *maximum* SA token expiration be ≥600s" — refuted; the 600s floor is on the *minimum* `expirationSeconds`, not a constraint on the configured max.
