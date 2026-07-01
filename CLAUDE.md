# nvidia-ida — zero-trust agentic platform (orientation for the main agent)

A homelab PoC proving a **credential-less agent** can **read delegated as a human** and **write (or use
premium models) only via human-approved, just-in-time, short-lived** elevation — the agent holds **only
its SPIFFE SVID**, never a stored broad credential. This now spans **two planes**: real **tools** (the
downstream sees the *user*) and AI **models** (the SVID *is* the model credential). Keep this invariant
in every change.

- **Cluster: `ocp-dev`** (3 control-plane + 2 worker, OCP 4.20.25). The old single-node `anaeem-sno`
  MELTED DOWN and was replaced — do **not** use `anaeem-sno.kubeconfig`.
  - `export KUBECONFIG=/home/anaeem/.kube/ocp-dev-admin.kubeconfig` — the **user token in
    `~/.kube/ocp-dev.kubeconfig` is EXPIRED**; the break-glass **cert** kubeconfig (`system:admin`,
    bypasses OAuth) is the working path. API `https://api.ocp-dev.na-launch.com:6443`, trust domain
    `anaeem.na-launch.com`, apps `*.apps.ocp-dev.na-launch.com` (ingress VIP `172.16.2.59`; `/etc/hosts`).
- **FRAGILE.** etcd is healthy (~150 MB, 3/3) but the control plane **flaps** (apiserver/oauth 5xx, slow
  `oc exec`); retry, don't panic. **READ-ONLY first; gate every mutation.** The **external Vault route is
  degraded** (`vault.apps.ocp-dev…` 503s on jwt/login) — services must use **in-cluster
  `http://vault.vault.svc:8200`**.
- **Authoritative status doc:** **`docs/PRD.md`** (requirement-by-requirement Done/Partial/Roadmap with
  live evidence + the open seams). **Install:** **`docs/install-guide.md`**. Phase-A history:
  `docs/reviews/phaseA-delegation-worklog-and-issues-2026-06-20.md`.
- **Per-session memory** (the real "context store"): `~/.claude/projects/-home-anaeem-nvidia-ida/memory/`
  (`MEMORY.md` is the index). Verify a memory's file/flag claims against live code before asserting them.

## The planes (do not conflate)
1. **TOOL plane — ext-proc → REAL tools (pfSense, k8s).** Agent SVID (UUID-shaped
   `…/ns/openshell/sandbox/<uuid>`) → `ext-proc-delegation` verifies it → reads the per-sandbox **Vault
   consent grant** (`secret/data/sandbox-grants/<uuid>`) → RFC 8693 on-behalf-of (currently the **static
   per-user token fallback** from Vault `mcp-tools/mcp-tokens{,-write}`) → injects the downstream token.
   Elevation = a **jit-approver capability JWT** minted only after a *different* human approves in the
   console (SoD). Proven on ocp-dev: read 200 → write 403 → mint → elevated write 200.
2. **MODEL plane — the SVID *is* the model credential (MaaS).** Agent SVID → Istio `maas-gateway` →
   Authorino validates the JWT-SVID vs **SPIRE-OIDC**, OPA authorizes the `…/sandbox/.+` sub →
   `llm-proxy` injects the OpenRouter key **server-side** from Vault → real completion. **No model key in
   the agent.** OpenRouter + an in-cluster KServe model are registered as **native RHOAI 3.4 Gen AI Studio
   assets**; `openrouter-bridge` (ns `maas`) makes the registered asset SVID-callable. Premium models fold
   into the *same* approve-to-elevate. Detail: `docs/design/maas-spiffe-auth.md`.
3. **Kagenti AuthBridge (ADR-0013), reaches echo-mcp.** SA-shaped SVID `…/ns/openshell/sa/openshell-sandbox`
   → spiffe-helper + authbridge-proxy → Keycloak federated-jwt → `jit-gate` → echo-mcp.

**SVID-shape mutual exclusion:** ext-proc needs the UUID path; Kagenti needs the SA path. The openshell
sandbox pod carries **TWO** SVIDs via two ClusterSPIFFEIDs (`openshell-sandbox-workloads` = SA-shaped,
`openshell-sandbox-extproc` = UUID-shaped); `svid_bearer` selects the UUID one via
`SVID_REQUIRE_PATH_SUBSTR=/sandbox/`. The model gateway ignores `aud`, so the same aud=mcp-gateway SVID
works for both planes.

## Current status (verified on ocp-dev)
- **Tool loop PROVEN** (read 200 / write 403 / mint+SoD / elevated write 200). **Model loop PROVEN** (no-token
  401 / SVID 200 real completion; the agent brain reasons via SVID; an openshell-namespaced sandbox SVID
  consumes OpenShift AI models SVID-only). **Gen AI Studio assets** registered (OpenRouter + MCP). **WORM
  audit** real: jit-approver on CNPG postgres with a tamper-evident hash-chain `jit_ledger` (append-only at
  the DB privilege level — `app` can't UPDATE/DELETE).
- **Agent brain = SVID-only via MaaS** (`maas_brain_proxy` → `/openrouter`). **LiteLLM is cut.** The
  launcher/console now default to SVID-only model boot (`SANDBOX_BRAIN_MAAS_SVID`, default on — commit
  `ec1356c`); the old stored-LiteLLM-key path is opt-out only.
- **Open seams** (PRD §5/§7/§8): real per-user OBO (static-token fallback today); GPU large-LLM (M7); one
  GitOps source of truth (zero ArgoCD apps actually applied — all imperative); native OpenShell launcher
  not deployed on ocp-dev (the `e2e-harness`/`openshell-maas-svid-proof` Deployments are the SVID-only proxies).

## Conventions & gotchas (save yourself the re-learning)
- **`oc delete` of CLUSTER-SCOPED resources is harness-DENIED** (clusterpolicy/clusterrole/clusterspiffeid/
  scc/crd) — and destructive deletes may be permission-gated. Namespaced deletes work; hand cluster-scoped reaps to the human.
- **ACM-hub reverter (CONFIRMED — reverts IMAGES *and* ENV).** The `mcp-gateway` deploys are reconciled by an
  ACM-hub ManifestWork that re-pins images AND **reverts `VAULT_ADDR` back to the external route within
  seconds** of any live `oc set env`. Repo overlays are now in-cluster; the **durable fix is a HUB edit**
  (no hub access from this cluster). Live `oc set env` holds only briefly.
- **Never whole-file `oc apply platform/spire/base/cluster-spiffe-ids.yaml`** — the live
  `agent-sandbox-e2e-harness` CSID drifts (hardcoded UUID). Apply per-doc.
- **OVN-K DNS egress** needs `:53` AND `:5353` to `openshift-dns`.
- **Kyverno on a CRD:** use `patchesJson6902` (append), not strategic-merge, on `containers`/`env` lists.
- **setns is CLOSED** (ADR-0017: `CAP_SYS_CHROOT` via Kyverno `mutate-openshell-sandbox-syschroot`, which
  fires on **every** pod in ns `openshell` with the `agents.x-k8s.io/sandbox-name-hash` label — a plain pod
  there needs an SCC allowing SYS_CHROOT, or use a different CSID/label to avoid it). Don't reopen.
- **`vault kv put -mount=secret <path> -`** (stdin JSON) writes grants with numeric types preserved (the
  vault pod lost `curl`); ext-proc's grant validation requires numeric `version`/`ttl`.

## Where things live
- SVIDs: `platform/spire/base/cluster-spiffe-ids.yaml` + `cluster-spiffe-id-openshell-sandbox-extproc.yaml`.
- Model plane: `platform/rhoai-maas/{spiffe-auth/,genai-studio/}` (gateway/OPA, OpenRouter+MCP Gen AI Studio
  assets, `openrouter-bridge`). WORM DB: `platform/jit-approver-db/`.
- Tool plane: `services/ext-proc-delegation/`, `services/jit-approver/` (+ `persistence/`, `ledger.py`),
  `services/approval-console/`, `services/sandbox-launcher/openshell.py`.
- Agent: `services/agent-sandbox/agent-harness/` (`maas_brain_proxy.py`, `svid_bearer.py`, `mcp-call`).
- Anchors: `hack/test-pfsense-jit-ocp-dev.sh` (the ocp-dev tool-journey anchor — uses `-k` + `scope_hash`).
- ADRs: 0011 (ext-proc), 0012 (pfSense tokens), 0013 (Kagenti+OBO), 0017 (setns), 0018 (SVID↔grant binding).

## Working state (git)
On branch **`fix/jit-approver-mint-route`**, **all committed + pushed**. Two remotes:
- `origin` → `git@git.arsalan.io:anaeem/nvidia-ida.git` (Gitea, the working remote; PR #54).
- `github` → `https://github.com/naeemarsalan/aegis-zero-trust-agentic.git` — **public**, scrubbed history
  (the 64 MB `services/ida-cli/ida` binary + `__pycache__` removed via `git filter-repo`). **The two
  histories diverged** (GitHub force-pushed); push to GitHub via a fresh clone of its `main`, never
  `git push github` from local (would re-add the binary / be non-fast-forward). The public **showroom docs**
  deploy to the **virt** cluster (`aegis.apps.virt.na-launch.com`). Cluster/repo access + push flow are in the
  local memory `reference-public-repo-and-docs-site` (not committed — keep credentials out of the repo).
