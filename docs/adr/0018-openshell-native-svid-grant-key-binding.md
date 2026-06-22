# ADR-0018: Native OpenShell sandboxes — ClusterSPIFFEID class gate + the SVID-path ↔ Vault-grant-key binding

- **Status:** Accepted — implemented and proven live 2026-06-20.
- **Date:** 2026-06-20
- **Related:** [ADR-0008](0008-svid-into-launched-sandbox.md) (SVID into launched sandbox), [ADR-0011](0011-e2e-via-openshell-native-or-variant-b.md) (the ext-proc hybrid), [ADR-0017](0017-provider-spiffe-setns-selinux-confinement.md) (the `CAP_SYS_CHROOT` setns fix), Phase-A plan `docs/plans/phase-A-openshell-native-loops.md`.
- **Supersedes the Loop A2 open decision** in the Phase-A plan (which label to bind on).

## Context

With the setns blocker closed (ADR-0017: `provider_spiffe` enabled at helm rev 7, `CAP_SYS_CHROOT` delivered via Kyverno, sandboxes run confined `container_t`), two defects still prevented a gateway-launched native sandbox from getting a usable delegated identity:

1. **No SVID was ever issued.** The `openshell-sandbox-workloads` `ClusterSPIFFEID` had an **empty `.status` / zero SPIRE entries** even with matching labelled pods. Root cause (confirmed live): it had **no `spec.className`**. The `spire-controller-manager` (the reconciler sidecar in `spire-server-0`) is class-gated — its ConfigMap sets `className: zero-trust-workload-identity-manager-spire`, and it **only reconciles CSIDs whose `spec.className` equals that value**. A CSID with no className is silently ignored. `className` perfectly partitioned the live CSIDs: every reconciled one (`...-spire-default` = 135 pods, `agent-sandbox-e2e-harness`) had it; every ignored one (`openshell-sandbox-workloads`, `agent-sandbox-workloads`, both `mcp-gateway-*`) did not.

2. **The label the CSID keyed on did not exist on the pod.** The committed CSID selected `openshell.ai/managed-by=openshell` and templated the SVID path off the pod **label** `openshell.ai/sandbox-id`. OpenShell 0.0.62 stamps **neither** as a pod label. A gateway sandbox pod carries only `agents.x-k8s.io/sandbox-name-hash=<8hex>` as a label; the OpenShell sandbox UUID is delivered onto the pod as the **annotation** `openshell.io/sandbox-id=<uuid>` (propagated from the Sandbox CR's podTemplate via the agent-sandbox controller's `agents.x-k8s.io/propagated-annotations`). The `openshell.ai/*` names exist only as **Sandbox CR labels**, never copied onto the pod.

These two combine into a hard binding requirement, because the delegated read on the ext-proc path is keyed by a single UUID that must agree on **three** independent surfaces:

- the **Vault grant key**: the `sandbox-launcher` writes the consent grant to `secret/data/sandbox-grants/<uuid>` where `<uuid> = resp.sandbox.metadata.id` (the OpenShell-assigned sandbox id) — `sandbox_launcher/api.py:463,483`;
- the **SVID path**: the `ClusterSPIFFEID` `spiffeIDTemplate` renders `spiffe://…/ns/openshell/sandbox/<uuid>` from a **pod** field;
- the **ext-proc lookup**: `sandboxUIDFromSub` (`ext-proc-delegation/internal/spire/spire.go`) parses the segment after `/sandbox/` from the SVID `sub` and reads `secret/data/sandbox-grants/<that-uuid>`.

If the SVID-path UUID ≠ the grant key, ext-proc `FetchGrant` 404s and the delegated read fails. The tentative fix of templating off the 8-hex `sandbox-name-hash` would have broken this (8-hex ≠ the full-UUID grant key).

## Decision

**1. Add the className gate.** Set `spec.className: zero-trust-workload-identity-manager-spire` on the `openshell-sandbox-workloads` CSID so the controller reconciles it. (Kept GitOps-durable in `platform/spire/base/cluster-spiffe-ids.yaml`.)

**2. Select on the label the pod actually has; template off the annotation that carries the grant key.**
- `podSelector`: `matchExpressions: [{key: agents.x-k8s.io/sandbox-name-hash, operator: Exists}]` — the universal sandbox-pod label (also excludes the `openshell-0` gateway pod). `podSelector` is a `LabelSelector`, so it can only match labels.
- `spiffeIDTemplate`: `spiffe://anaeem.na-launch.com/ns/{{ .PodMeta.Namespace }}/sandbox/{{ index .PodMeta.Annotations "openshell.io/sandbox-id" }}`. The `spiffeIDTemplate` data context's `.PodMeta` is the **full `*metav1.ObjectMeta`** (spire-controller-manager `pkg/spireentry/entries.go`), so `.Annotations` is readable. A missing annotation renders an **empty** path segment, so ext-proc fails closed — the safe outcome. The `openshell.io/sandbox-id` annotation value equals `resp.sandbox.metadata.id`, i.e. the Vault grant key.

This makes the binding hold by construction: **`resp.sandbox.metadata.id` == pod annotation `openshell.io/sandbox-id` == SVID `/sandbox/<uuid>` == Vault grant key.**

**3. The launcher writes the grant; ext-proc reads it.** The `sandbox-launcher` writes `{version, sandbox_uid, user, scope, ttl, nonce, created}` to `secret/data/sandbox-grants/<metadata.id>` on CreateSandbox, gated by a least-privilege Vault policy (`platform/vault/config/sandbox-launcher.hcl`: `create/update` on the grants sub-tree, `read` on its own OIDC secret, deny all else). This is the asymmetric write counterpart to ext-proc's read (`ext-proc.hcl`).

We deliberately did **not** add `className` to the other three ignored CSIDs (`agent-sandbox-workloads`, `mcp-gateway-*`) — they are covered by the class-matched `…-spire-default` CSID and may be intentionally inert; activating them is a separate, gated decision.

## Evidence (proven live 2026-06-20)

- After the className+annotation fix, `openshell-sandbox-workloads.status.stats` = `podsSelected:7, entriesToSet:7, podEntryRenderFailures:0, entryFailures:0`; `spire-server entry show` lists 7 `…/ns/openshell/sandbox/<uuid>` entries whose UUIDs match the pods' `openshell.io/sandbox-id` annotations. `…-spire-default` (135 pods) and the working `agent-sandbox-e2e-harness` CSID were unregressed.
- A freshly launched sandbox (`agent-service-account-sand-188e4b`, id `bee07868-…`) produced: launcher log `vault_grant_write_ok` + `grant_written`; a Vault grant at `secret/data/sandbox-grants/bee07868-…` with `ttl:1800, scope:read-only`; a SPIRE entry `…/sandbox/bee07868-…`; pod annotation `openshell.io/sandbox-id == bee07868-… == grant key` (**binding match**); the workload-API socket mounted; `SYS_CHROOT` present; confined `container_t:s0:c291,c950`; **zero setns/EPERM**.
- The proven Variant-B journey (`hack/test-openshift-jit.sh`) stayed **4/4** after every change.

## Invariant preservation

Every change only governs how the sandbox's **own** short-lived SVID is minted, or writes a **consent record** (never a credential — `vault.write_sandbox_grant` rejects any document carrying `access_token/bearer/svid/private_key/…`). The agent holds only its SVID; the launcher verifies then **discards** the caller's token, persisting only the verified identity string. Reads are delegated on-behalf-of the user; writes remain JIT-gated downstream. No long-lived, broadly-scoped credential is stored in or forwarded by the agent.

## Consequences

- **Loops 1+2 (the native delegation substrate) are shipped and proven:** a gateway-launched sandbox gets a registered+delivered SVID and a correctly-keyed Vault grant, with the binding holding end-to-end.
- **Loop 3 (the agent-driven hybrid acceptance) remains:** delegated read `200` → dangerous tool `403` → console-approved JIT → retry `200` → post-TTL `403`. This needs the in-sandbox agent's MCP traffic to flow **through ext-proc carrying the raw SVID** (so ext-proc resolves the grant per ADR-0011's retained-hybrid posture) **and** the agent-brain reachable from ns `openshell`. Verified: a fresh sandbox is substrate-ready; not yet verified: the agent autonomously driving that read (ext-proc saw no native traffic — the agent session did not call a tool). Captured in `hack/test-openshell-native-hybrid.sh` (substrate = hard gate; agent-driven read = reported, hard only under `REQUIRE_AGENT_READ=1`).
- **Compensating control still open (review item):** ns `openshell` has only an SSH ingress NetworkPolicy; an egress NetworkPolicy should land before Phase A closes (`SYS_CHROOT`+`SYS_ADMIN` sandboxes should not egress arbitrarily). `platform/openshell/networkpolicy-sandbox-egress.yaml` exists but is not yet applied.
- **Latent landmine flagged (not fixed here):** the committed `agent-sandbox-e2e-harness` CSID drifts from live (git = templated; live = a hardcoded literal UUID + the `nvidia-ida/purpose` label + className). A whole-file `oc apply` of `cluster-spiffe-ids.yaml` would rewrite the working harness SVID — apply per-CSID until the harness block is reconciled to live. A descriptive comment was added in-file.
