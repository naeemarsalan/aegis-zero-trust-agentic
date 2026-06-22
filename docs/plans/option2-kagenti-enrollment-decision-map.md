# Option 2 — situation map: where we are, what we're stuck on, how it fits the strategy

Written 2026-06-20 to re-align after going deep into plumbing. Plain-language map.

## 1. The strategy (what we're ultimately proving)

A **credential-less agent inside an OpenShell sandbox** that:
- **reads** infrastructure with a delegated identity, and
- **writes** only with **human-approved, just-in-time, short-lived** elevation.

The agent holds **only its SPIFFE SVID** — no stored broad credential. This single loop is the
proof the whole platform rests on. "Phase A" = make this loop work for a sandbox launched
natively through the OpenShell gateway. Phases B/C are blocked until Phase A is green.

## 2. The root of the confusion: there are TWO identity paths in this repo

| | **Path A — ext-proc (original bespoke build)** | **Path B — Kagenti AuthBridge (chosen go-forward, ADR-0013)** |
|---|---|---|
| Mechanism | sandbox SVID → mcp-gateway's **ext-proc** → reads a **Vault consent grant** (launcher wrote it: user=X, scope) → RFC 8693 **on-behalf-of** exchange | sandbox SVID → **spiffe-helper** sidecar → **AuthBridge** sidecar → Keycloak **federated-jwt** + token-exchange |
| What the MCP sees | **the USER** (user=arsalan) — true delegation | **the AGENT's own SPIFFE identity** (agent-attributed), NOT the user |
| Writes / JIT | our jit gate | our jit-gate (kept on top — Kagenti doesn't do human-approval) |
| Status | the PROVEN Variant-B 4/4 journey (ns agent-sandbox) | PROVEN 4/4 for a test agent (ns kagenti-test) |
| Decision | being **retired** (ADR-0013) | the **chosen direction** (ADR-0013 + your call) |

**This is the strategic fork.** Path A = "MCP sees the user." Path B = "MCP sees the agent."
You've said Kagenti is the direction → **Path B** → agent-attributed identity, with the human tied
in via (a) the JIT approval for writes and (b) the launcher recording which human launched the
sandbox. **If we actually need "MCP sees user=arsalan," that's Path A and a different build.**

## 3. What's DONE this session (Phase A substrate) — and which path each piece serves

| Done | Serves |
|---|---|
| **Loop 1** — sandbox gets a per-sandbox SVID (ClusterSPIFFEID className+annotation fix, ADR-0018) | **BOTH** A & B (spiffe-helper and ext-proc both need the SVID) |
| **Loop 2** — launcher writes the Vault consent grant | **Path A only** (Kagenti has no grant concept) |
| DNS / egress NetworkPolicy fix (the `:5353` bug) | hardening, both |
| 4/4 baseline held; etcd defragged 1.0GB→787MB | safety |

So: Loop 1 is useful regardless. Loop 2 (the grant) is **only** used by Path A — on Path B it's inert.

## 4. The ONE thing we got stuck on (it's small, and it's pure plumbing)

To turn on **Path B**, Kagenti's injector must add the AuthBridge sidecar to the sandbox pod.
The injector only fires on pods carrying the label **`kagenti.io/type=agent`**.

> **The OpenShell gateway creates sandbox pods WITHOUT that label.**

That's the entire stuck point. Everything in the last several turns was: *how do we get that one
label onto a gateway-created pod at creation time?*

```
gateway → Sandbox CR → [agent-sandbox controller] → Pod  → [Kagenti injector checks label] → inject sidecars?
                                                     ^^^^
                              the label must already be here when the injector looks
```

Three ways to add the label, and what we learned:

1. **Kyverno mutate the POD** → ❌ FAILED. Kubernetes evaluates the injector's label-filter on the
   pod's *original* labels; Kyverno adds the label *after* that check → injector never fires.
   (Proven live this session.)
2. **Deploy kagenti's `openshell-driver-openshift`** → ⚠️ It sets the label natively, BUT it only
   works with the **kagenti gateway *fork*** (`quay.io/azaalouk/...`). Your NVIDIA gateway 0.0.62
   has no external-driver support. So this = **swap the entire gateway** to an unsigned personal
   fork + different config format + different supervisor + unknown SQLite migration + **lose the
   SPIFFE integration we just built**. Very high risk on a single-node cluster. (Confirmed in source.)
3. **Kyverno mutate the SANDBOX CR** (not the pod) → ✅ Clean. The agent-sandbox controller copies
   `spec.podTemplate.metadata.labels` onto the pod *at creation* (confirmed in controller source),
   so the label is present *before* the injector looks. **Same end result as the driver, zero
   gateway change, keeps SPIFFE.**

## 5. My assumptions (please confirm or correct)

1. Go-forward identity model = **Path B** (Kagenti AuthBridge, agent-attributed + our JIT), not Path A.
2. **Agent-attributed identity is acceptable** — the MCP seeing the agent's SVID (not user=arsalan)
   meets the bar, because the human is tied in via JIT approval + the launcher's record of who
   launched it. *(This is the crux — if false, we're on Path A.)*
3. We want the sandbox agent to reach the **real MCP tools** (pfsense/k8s) via the existing
   mcp-gateway → AuthBridge's exchanged token must be accepted by the mcp-gateway. **This is an
   open integration question I have NOT solved** (the proven kagenti-test used a separate echo-mcp).
4. Realm `kagenti` (isolated, already proven) is fine.

## 6. How this fits the strategy

- "Option 2" = the in-sandbox agent actually performing the delegated read (+ JIT write). Path B
  is the mechanism. The label-stamping is just the **enrollment switch** that turns Path B on for
  OpenShell sandboxes.
- Once enrolled, the loop is: sandbox agent → AuthBridge → MCP (read, agent-attributed) → jit-gate
  (write, human-approved). That's the Phase-A goal on the Kagenti path.

## 7. The decision workflow (what unblocks us)

```
Q1. Is agent-attributed identity (Path B) the accepted model?
     ├─ YES → proceed Path B (below)
     └─ NO  → we need on-behalf-of-USER → that's Path A (ext-proc), a different build → stop & re-scope

Q2. (Path B) How to stamp kagenti.io/type=agent on the pod?
     → Kyverno-on-Sandbox-CR  (recommended: zero gateway risk, proven mechanism)
       vs gateway-fork-swap   (high risk, only if the driver's extra features are needed)

Q3. (Path B) Open integration question to solve BEFORE it's end-to-end:
     Does the mcp-gateway accept AuthBridge's exchanged token for the REAL tools (pfsense/k8s)?
     The kagenti-test proof used echo-mcp, not the real mcp-gateway. Needs a small spike.

Then: enroll one sandbox → curl-through-proxy test (no LLM credits needed) → verify identity chain
→ wire jit-gate for writes → done. (Full LLM-driven run also needs OpenRouter credits topped up.)
```

## 8. Current applied state (nothing broken; all inert)

Still on the cluster from the failed Kyverno-on-pod attempt: ns `openshell` label
`kagenti-enabled=true`, a dead pod-level Kyverno policy, the 5 AuthBridge config CMs, and one test
sandbox. None of it injects anything (the label-ordering failure), so sandbox creation is normal.
Easy to roll back or to reuse for the Kyverno-on-CR approach.
