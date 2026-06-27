# openshell-maas-svid-proof

Proves: **a pod in `ns openshell` holding ONLY an openshell sandbox-shaped SPIFFE SVID
(no model key) consumes OpenShift AI models with only its SVID.** It answers
"does OpenShell work with the SVID/SPIFFE from OpenShift AI?" — **yes, at the
identity→model leg**, on the real `openshell` namespace with the real model gateway.

## What ran (ocp-dev, 2026-06-27 — verified)
Same `agent-harness:maas-brain` image + `maas_brain_proxy` a native sandbox boots,
SVID-only (`MAAS_BRAIN=1`, no model key):

| Check | Result |
|---|---|
| SVID the pod presents | `spiffe://anaeem.na-launch.com/ns/openshell/sandbox/maas-svid-proof` (aud `mcp-gateway`) |
| Model key in pod env | **none** (only the loopback proxy) |
| Brain reasons via SVID → OpenShift AI MaaS gateway → model | **HTTP 200**, content `OPENSHELL-SVID-OK` |
| Negative control: no SVID → maas-gateway | **HTTP 401** (fail-closed) |

The `…/ns/openshell/sandbox/…` sub matches the model gateway's `maas-spiffe-auth` OPA
regex `^…/ns/(openshell|agent-sandbox)/sandbox/.+$` — the exact identity a native
sandbox is authorized under. Authorino validates the JWT-SVID vs SPIRE-OIDC; `llm-proxy`
injects the OpenRouter key server-side from Vault (never in the pod).

## Honest scope — what this does NOT prove
- It uses a **dedicated ClusterSPIFFEID** (`app`-label) that yields the *same SVID shape*
  as the launcher-issued per-UUID CSID — chosen to avoid the `sandbox-name-hash` label that
  triggers the syschroot Kyverno mutation + full native confinement admission stack.
- It is a **Deployment, not a launched `Sandbox` CR**, so it SKIPS the native lifecycle, the
  OpenShell gateway forward-proxy/Landlock egress confinement, the runc setns/MCS +
  `CAP_SYS_CHROOT` isolation, and the per-sandbox Vault consent grant (the model path needs
  no grant — the SVID alone authorizes at the gateway).

## Open product gap (surfaced by workflow wf_99506aa8-546)
The **current launcher code injects a stored LiteLLM key** (`openshell.py _brain_env` sets
`ANTHROPIC_AUTH_TOKEN/BASE_URL` → LiteLLM `172.16.2.251:4000`), so a sandbox launched by
*today's product path* would consume the model with a **stored credential, not its SVID**.
The SVID-only path (`bin/brain-entrypoint` + `MAAS_BRAIN=1`, no model key — what this proof
uses) must become the launcher default to make the product match the invariant.

## Files
- `deployment.yaml` — the restricted-v2 proof pod (SVID-only brain).
- `clusterspiffeid.yaml` — dedicated CSID issuing the openshell sandbox-shaped SVID.
- `rbac.yaml` — the SA + an `openshell-sandbox-syschroot` SCC (the SCC a *real* native
  sandbox SA needs for the syschroot mutation; provided for the future native bring-up).
