# jit-approver

Just-in-time Kubernetes credential escalation service. Agents request short-lived
namespace-scoped credentials via a Gitea PR. A human (or automated policy) approves
by merging the PR. PR-merge is the audit record — no Slack, no out-of-band channel.

## What / Why

Zero-trust agents run with minimal standing permissions. When an agent needs elevated
access (e.g. `create pods` in `agent-sandbox` for a 15-minute debugging window) it
calls the jit-approver API. The approver:

1. Validates scope at the edge (no delete/escalate/impersonate; no secrets/roles;
   namespace must be in allowlist; duration 1–60 minutes).
2. Creates a Gitea branch `jit/<session-id>`, commits a reviewable YAML grant document
   to `grants/<session-id>.yaml`, and opens a PR labelled `jit-approval`.
3. An approver merges the PR — Gitea fires a webhook.
4. The webhook receiver verifies HMAC-SHA256 signature, confirms the merge is on `main`
   with the `jit-approval` label, then calls Vault to issue a short-lived Kubernetes
   service account token scoped to exactly what was requested.
5. **Credential delivery (UC2).** On issuance the approver:
   - writes the SA token to Vault KV `secret/data/jit/<session-id>` (durable tracking /
     audit / revocation copy), and
   - mints a short-lived RS256 **session-capability JWT** (`X-JIT-Session-JWT`) scoped to
     the approved dangerous MCP tool name(s) via a `tool_scope` claim, signed by the
     jit-approver key (`kid` `jit-approver-key-1`; public keys at `GET /jwks`).
   The agent receives **both** the SA token and the session JWT from
   `GET /requests/<id>/status` once `state==issued`, over the authenticated SVID-mTLS
   channel — they are **never** returned before issuance. The agent wields the SA token to
   act (that IS UC2) and presents the session JWT as `X-JIT-Session-JWT` on the dangerous
   tool call so the Kyverno `dangerous-tools-admins-only` gate (which verifies it against
   `/jwks`) admits the call.

   > This supersedes the original "Vault injector reads the KV path into the pod at start"
   > delivery, which is impossible for a dynamically-created session (the pod would need the
   > token before the session exists — chicken-and-egg). The session JWT is the agent's
   > **own** scoped, signed, short-lived capability, **not** a downstream service credential,
   > so this does not violate the no-downstream-credential-passing invariant (which targets
   > UC1 ext-proc-proxied creds).

## Sequence Diagram

```
Agent Pod          jit-approver           Gitea             Vault KV
   |                    |                   |                   |
   |--POST /requests--->|                   |                   |
   |   (EscalationReq)  |                   |                   |
   |                    |--create branch--->|                   |
   |                    |--commit YAML----->|                   |
   |                    |--open PR--------->|                   |
   |<--202 {id,pr_url}--|                   |                   |
   |                    |                   |                   |
   |             [Human reviews and merges PR]                  |
   |                    |                   |                   |
   |                    |<--webhook merge---|                   |
   |                    | (HMAC verified)   |                   |
   |                    |<--GET raw grants/<id>.yaml (merged)--|     |
   |                    |  (re-validate reviewed scope)        |     |
   |                    |--Vault login------------------------------>|
   |                    |--CREATE kubernetes/roles/jit-<id>--------->|
   |                    |--kubernetes/creds/jit-<id> --------------->|
   |                    |--KV PUT secret/data/jit/<id>-------------->|
   |                    |                   |                   |   |
   |                    |  [mint RS256 session JWT (tool_scope, /jwks)]    |
   |--GET /requests/id/status               |                   |   |
   |<--{state:issued, expires_at, sa_token, session_jwt}-------|   |
   |                                        |                   |   |
   | [Agent presents X-JIT-Session-JWT to the Kyverno gate, wields    ]
   |   sa_token to act for the approved window, then posts summary    ]
   | [Reaper deletes kubernetes/roles/jit-<id> + KV record at expiry  ]
   |--POST /requests/id/summary------------>|                   |
   |                    |--PR comment------>|                   |
   |<--200 {recorded}---|                   |                   |
```

## Apply Order

```
# Prerequisites (must already exist):
#   namespace mcp-gateway (created by agentgateway component)
#   Vault Agent Injector running (vault component)
#   SPIFFE CSI driver (ztwim-spire component)

# 1. Pre-populate Vault secrets (run once):
vault kv put secret/data/jit-approver/gitea-token token=<gitea-api-token>
vault kv put secret/data/jit-approver/webhook-secret secret=<random-32-bytes>

# 2. Configure Vault JWT auth role for jit-approver:
vault write auth/jwt/role/jit-approver \
  bound_audiences="https://vault.apps.anaeem.na-launch.com" \
  bound_subject="spiffe://anaeem.na-launch.com/ns/mcp-gateway/sa/jit-approver" \
  user_claim="sub" \
  policies="jit-approver" \
  ttl=1h

# 3. Vault Kubernetes secrets engine — EPHEMERAL per-session roles (H3):
#    The approver does NOT use a single static role. At issuance time it CREATES
#    kubernetes/roles/jit-<session-id> from the reviewed verbs/resources, with
#    allowed_kubernetes_namespaces=[approved ns] and token TTL = the approved
#    window, then reads kubernetes/creds/jit-<session-id> once. The reviewed
#    scope is therefore the ENFORCED scope.
#
#    The jit-approver policy must allow create/update + read on the jit-* role
#    path (added by the vault-config fixer):
#      path "kubernetes/roles/jit-*"  { capabilities = ["create","update","read","delete"] }
#      path "kubernetes/creds/jit-*"  { capabilities = ["create","update"] }
#
#    No static jit-scoped role write is needed anymore.

# 4. Apply kustomize:
kustomize build services/jit-approver/deploy/overlays/anaeem | kubectl apply -f -
```

### Cleanup / expiry reaper (N3 — implemented in-process)

Each approval creates an ephemeral Vault role `kubernetes/roles/jit-<session-id>`
plus a KV record `secret/data/jit/<session-id>`. The approver runs an in-process
**reaper** background task (started at app startup, `reaper.py`) that sweeps every
~60s and, for sessions whose `expires_at` has passed, **deletes the ephemeral Vault
role and the KV record** (`secret/metadata/jit/<id>`) and marks the session
`expired`. A leaked ephemeral role is standing scope that outlives the approval
window, so this closes that hole. The jit-approver Vault policy already grants
`delete` on `kubernetes/roles/jit-*`.

The reaper is test-friendly: `reap_once(now=..., http=...)` runs a single
deterministic sweep with an injectable clock + client. Set `JIT_DISABLE_REAPER=1`
to skip starting the background loop (used by the test suite, which drives
`reap_once()` directly).

### Signing key for the session JWT (N1)

The session-capability JWT is signed RS256. Provide a stable PEM private key at
`JIT_SIGNING_KEY_PATH` (Vault-injected at `/vault/secrets/jit-signing-key`) so the
JWKS — and already-issued tokens — survive restarts. If the file is absent the
service generates an **ephemeral** RSA-2048 keypair at startup (PoC only). Public
keys are served unauthenticated at `GET /jwks` with `kid` `jit-approver-key-1`,
which is exactly the URL the Kyverno `dangerous-tools-admins-only` policy fetches.

## Verify

```bash
# Check pod is running
kubectl get pods -n mcp-gateway -l app=jit-approver

# Health check
kubectl exec -n mcp-gateway deploy/jit-approver -- \
  curl -s http://localhost:8080/healthz

# Check route is accessible
curl -sk https://jit-approver.apps.anaeem.na-launch.com/webhooks/gitea \
  -X POST -H "X-Gitea-Event: ping" -d '{}' 2>&1
# Expected: 401 (missing signature) — confirms route reaches the service
```

## Gitea Webhook Setup

1. In Gitea, navigate to **Repository Settings > Webhooks > Add Webhook > Gitea**.
2. Target URL: `https://jit-approver.apps.anaeem.na-launch.com/webhooks/gitea`
3. Content type: `application/json`
4. Secret: the value stored in `vault kv get secret/data/jit-approver/webhook-secret`
5. Trigger: **Pull Request** events only (closed/merged is what matters)
6. Create the `jit-approval` label in the repository (Settings > Labels > Create Label)

## Vault Auth — PoC vs Production

### PoC (current implementation)

The SVID JWT is read from a file path (`SVID_JWT_PATH`, default `/var/run/secrets/svid.jwt`).
This file is written by a SPIFFE workload API helper or Vault Agent sidecar before the
jit-approver process starts. The JWT is then POSTed to `/v1/auth/jwt/login`.

### Production (recommended)

Use [py-spiffe](https://github.com/HewlettPackard/py-spiffe) with the workload socket:

```python
from spiffe import SpiffeWorkloadApiClient

async with SpiffeWorkloadApiClient() as client:
    svid = await client.fetch_jwt_svid(audiences=["https://vault.apps.anaeem.na-launch.com"])
    jwt = svid.token
```

The workload socket path is injected by the SPIFFE CSI driver at
`/var/run/secrets/spiffe.io/` and the environment variable `SPIFFE_ENDPOINT_SOCKET`
is set automatically.

## Security Invariants

- Token is written to Vault KV (`secret/data/jit/<session-id>`), never returned over HTTP
- Scope ceiling enforced at validation time (pre-Gitea): no delete/escalate/impersonate,
  no secrets/roles/rolebindings/clusterroles, namespace must be in allowlist, max 60m
- HMAC-SHA256 signature verification on every webhook call; fail-closed on missing secret
- Audit events emit `justification_hash` and `action_hashes` (sha256) — raw args never logged
- NetworkPolicy: ingress only from agent-sandbox pods and router (webhook path), egress
  only to DNS, Gitea (172.16.0.0/12:443), and Vault

## Egress Network Notes

- **Gitea** (`git.arsalan.io`): resolves to an IP in `172.16.0.0/12`. The NetworkPolicy
  uses this CIDR. To lock it down further, resolve the IP and replace with `/32`.
  Run `nslookup git.arsalan.io` from within the cluster to confirm.
- **Vault**: allowed via both direct service (`vault:8200`) and the OCP Route
  (`vault.apps.anaeem.na-launch.com` via router :443).
