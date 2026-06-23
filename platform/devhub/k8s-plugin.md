# RHDH Kubernetes plugin — surfacing the Sandbox CR and JIT grants on an entity page

This document describes the configuration that lets a Red Hat Developer Hub
(RHDH) **entity page** show the live OpenShell `Sandbox` custom resource a user
launched (via the *Run an Agent* template) plus any JIT privilege-grant objects
tied to it — directly on the **Kubernetes** tab of the entity.  It also
describes how to surface the Forgejo JIT approval PR queue as a zero-plugin
navigational link on the entity Overview tab using `spec.links`.

> All snippets below are **operator wiring**. They must be **merged by hand**
> into the live config on the `anaeem` cluster. Do **not** apply them
> automatically and do **not** edit the live RHDH ConfigMaps from a pipeline.
>
> Drive the cluster with:
> ```
> oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify ...
> ```

The complete `kubernetes:` app-config stanza is in
`platform/devhub/app-config-k8s.yaml` — use that as the merge source for step 1.

---

## 0. What's already in place (anaeem)

- The `kubernetes` frontend + backend dynamic plugins are **enabled** in the
  `developer-hub-dynamic-plugins` ConfigMap.
- `developer-hub-app-config` already has a `kubernetes:` stanza with the
  `anaeem` cluster configured using `authProvider: serviceAccount` and
  `skipTLSVerify: true`.
- What is **missing**: the `kubernetes.customResources` array (so the plugin
  knows about `agents.x-k8s.io/sandboxes`) and the matching RBAC for the RHDH
  ServiceAccount token.

The Sandbox CR group/version is confirmed from
`platform/openshell/sandbox-capstone.yaml`:
`apiVersion: agents.x-k8s.io/v1alpha1`, `kind: Sandbox`, plural `sandboxes`.

### 0a. Dynamic plugin package paths (verify before touching the ConfigMap)

Both plugins ship bundled in the RHDH image — no registry pull, SNO/air-gap safe.

| Role | ConfigMap entry `package` value |
|------|---------------------------------|
| Frontend | `./dynamic-plugins/dist/backstage-plugin-kubernetes` |
| Backend  | `./dynamic-plugins/dist/backstage-plugin-kubernetes-backend-dynamic` |

Note: the backend path ends in **`-dynamic`**; the frontend does not.

If either is missing from the `developer-hub-dynamic-plugins` ConfigMap `plugins:`
list, add it with `disabled: false`:

```yaml
# In developer-hub-dynamic-plugins ConfigMap, under plugins:
- disabled: false
  package: ./dynamic-plugins/dist/backstage-plugin-kubernetes
- disabled: false
  package: ./dynamic-plugins/dist/backstage-plugin-kubernetes-backend-dynamic
```

The `if.anyOf` trigger in the bundled `app-config.dynamic-plugins.yaml` enables
the Kubernetes tab on any entity carrying `backstage.io/kubernetes-id` **or**
`backstage.io/kubernetes-namespace` — no extra wiring needed once both plugins
are enabled.

---

## 1. Teach the plugin about the Sandbox CRD

Merge this into `developer-hub-app-config` → `data.app-config.yaml`, **under the
existing `kubernetes:` key** (add only the `customResources` block — keep the
existing `clusterLocatorMethods`):

```yaml
kubernetes:
  serviceLocatorMethod:
    type: multiTenant
  clusterLocatorMethods:
    - type: config
      clusters:
        - name: anaeem
          url: https://api.ocp-dev.na-launch.com:6443
          authProvider: serviceAccount
          serviceAccountToken: ${K8S_ANAEEM_TOKEN}
          skipTLSVerify: true
          skipMetricsLookup: true
  # ---- ADD THIS BLOCK ----
  customResources:
    - group: agents.x-k8s.io
      apiVersion: v1alpha1     # version ONLY — not "agents.x-k8s.io/v1alpha1"
      plural: sandboxes
```

Gotcha: `customResources[].apiVersion` takes **only the version part**
(`v1alpha1`). The group is the separate `group` field. Combining them
(`agents.x-k8s.io/v1alpha1`) makes the plugin silently fail to list the CR.

If JIT grants are modeled as their own CRD (e.g. an `escalations.agentic.io`
`Grant` object the JIT flow writes), add a second entry so they appear on the
same tab:

```yaml
  customResources:
    - group: agents.x-k8s.io
      apiVersion: v1alpha1
      plural: sandboxes
    - group: agentic.io            # adjust to the real JIT grant CRD group
      apiVersion: v1alpha1
      plural: grants
```

---

## 2. Grant the RHDH ServiceAccount RBAC to read those CRs

The token in `${K8S_ANAEEM_TOKEN}` is what the kubernetes backend uses to list
resources. It needs `get`/`list`/`watch` on the Sandbox CR (and on the JIT grant
CR, if used) cluster-wide, plus the standard workload reads the plugin already
relies on.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: rhdh-kubernetes-sandbox-reader
rules:
  - apiGroups: ["agents.x-k8s.io"]
    resources: ["sandboxes"]
    verbs: ["get", "list", "watch"]
  # JIT grant CRD — adjust group/resource to the real type, or remove.
  - apiGroups: ["agentic.io"]
    resources: ["grants"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: rhdh-kubernetes-sandbox-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: rhdh-kubernetes-sandbox-reader
subjects:
  # The ServiceAccount whose token is wired into K8S_ANAEEM_TOKEN.
  - kind: ServiceAccount
    name: developer-hub-kubernetes      # adjust to the real SA name
    namespace: rhdh
```

Confirm the SA backing `K8S_ANAEEM_TOKEN`, then bind to it:

```
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  -n rhdh get secret | grep token
```

---

## 3. Annotate the entity so the plugin knows which objects to show

The Kubernetes tab is triggered by entity annotations.  There are two entity
types that need annotations — the static **mcp-server Resources** in
`catalog/` and the transient **Sandbox entity** the launcher emits per run.

### 3a. Static mcp-server Resources (`catalog/pfsense.yaml`, `catalog/echo.yaml`)

These Resources represent the MCP gateway capabilities, not individual sandboxes.
They should NOT carry `backstage.io/kubernetes-id` because there is no single
cluster object whose lifecycle mirrors the gateway Resource.  Leave the existing
`metadata.annotations` in those files as-is (only `backstage.io/source-location`
and the `nvidia-ida/*` annotations).

The Kubernetes tab will not appear on these entities — which is correct.  The
gateway pods (if you later want to surface them) would require their own
entity and annotations scoped to the `agentic-mcp` namespace.

### 3b. Launched Sandbox entity (transient `catalog-info.yaml` emitted by the launcher)

The catalog entity the launcher emits (or registers via `catalog:register`) must
carry:

```yaml
metadata:
  name: <sandbox-name>                # e.g. arsalan-task-20260613-a3f2
  annotations:
    backstage.io/kubernetes-id: <sandbox-name>
    backstage.io/kubernetes-namespace: agent-sandboxes
```

`backstage.io/kubernetes-id` is the value the plugin uses to build the label
selector `backstage.io/kubernetes-id=<sandbox-name>`.  Setting
`backstage.io/kubernetes-namespace` scopes the lookup to `agent-sandboxes` so
the plugin does not fan out cluster-wide across all namespaces.

Do **not** set `backstage.io/kubernetes-cluster` — that annotation is only valid
with `singleTenant` serviceLocatorMethod and will be ignored or cause errors with
the `multiTenant` method this platform uses.

Alternative: use a custom label selector instead of the `kubernetes-id` shorthand:

```yaml
metadata:
  annotations:
    backstage.io/kubernetes-label-selector: "agentic.io/sandbox=<sandbox-name>"
    backstage.io/kubernetes-namespace: agent-sandboxes
```

Use either `kubernetes-id` or `kubernetes-label-selector` — not both.

---

## 4. Label the Sandbox CR (and JIT grant objects) so they match

For the plugin to find an object, the object itself must carry the label that
the entity's `kubernetes-id` produces. The launcher must stamp the Sandbox CR
(and any JIT grant it later creates for that sandbox) with:

```yaml
metadata:
  labels:
    backstage.io/kubernetes-id: <sandbox-name>
```

A JIT grant created for the same sandbox should carry the **same** label so it
renders on the same entity's Kubernetes tab next to the Sandbox CR:

```yaml
# example JIT grant object the escalation flow writes
metadata:
  name: <sandbox-name>-grant-pfsense-create
  labels:
    backstage.io/kubernetes-id: <sandbox-name>
```

---

## 5. End-to-end flow

1. User runs the **Run an Agent** template.
2. Launcher creates a `Sandbox` (group `agents.x-k8s.io`, plural `sandboxes`)
   in `agent-sandboxes`, labeled `backstage.io/kubernetes-id=<sandbox-name>`,
   and emits a `catalog-info.yaml` carrying the matching
   `backstage.io/kubernetes-id` + `backstage.io/kubernetes-namespace`
   annotations.
3. RHDH ingests the entity; the **Kubernetes** tab queries the `anaeem` cluster
   with the RHDH SA token and lists the Sandbox CR (because `customResources`
   declares it) plus its pods/PVCs.
4. When the user requests a privileged tool and JIT approval writes a grant
   object with the same label, that grant appears on the same tab — giving a
   single pane showing the sandbox **and** its active grants.

---

## 5a. MVP approvals surface — JIT grant PR queue via `spec.links`

There is no Forgejo PR plugin in RHDH 1.x and no built-in annotation that
auto-surfaces a PR list on an entity page.  The zero-plugin approach is
`spec.links`: RHDH core renders every `spec.links` entry as a clickable card
in the **Links** widget on the Overview tab, regardless of the `type` field.

Add the following to the Sandbox entity's `spec.links` in the transient
`catalog-info.yaml` the launcher emits:

```yaml
spec:
  links:
    # Forgejo PR queue filtered to open jit-grant PRs — one click to the approval queue.
    #
    # IMPORTANT — Forgejo/Gitea `labels=` query param: the pulls list endpoint
    # accepts numeric label IDs, not label name slugs.  Before using this URL,
    # look up the numeric ID of the `jit-grant` label in the Forgejo UI (or via
    # the Forgejo API: GET /api/v1/repos/anaeem/nvidia-ida/labels) and replace
    # `<jit-grant-label-id>` with the actual integer (e.g. `labels=12`).
    # Without the correct numeric ID the `labels=` filter is silently ignored and
    # the link lands on the unfiltered open-PR list; it still navigates correctly
    # but does NOT pre-filter to jit-grant PRs.
    #
    # The `type` filter for the pulls list accepts: all / assigned / created /
    # mentioned / review_requested.  `type=comment` is not a valid value and is
    # silently ignored — omit it.  `state=open` alone is sufficient.
    - url: https://git.arsalan.io/anaeem/nvidia-ida/pulls?state=open&labels=<jit-grant-label-id>
      title: Pending JIT grant requests
      icon: github
      type: jit-pr-list
    # Direct link to the running sandbox in the OpenShift console.
    - url: https://console-openshift-console.apps.ocp-dev.na-launch.com/k8s/ns/agent-sandboxes/agents.x-k8s.io~v1alpha1~Sandbox/<sandbox-name>
      title: Sandbox in OpenShift console
      icon: dashboard
```

The `type: jit-pr-list` field is free-form; RHDH core does not filter or act on
`type` — it is available for future custom card plugins.  The `icon` values
`github` and `dashboard` are commonly mapped in RHDH app-defaults; unmapped
icons fall back to a default glyph.  The `spec.links` icon field is
integrator-supplied — the Backstage descriptor spec does not guarantee any
specific icon set across releases.

**What this gives you (MVP):** a single click from the entity Overview tab to the
Forgejo PR list filtered to open PRs.  Once you substitute the correct numeric
label ID (see URL comment above), the link pre-filters to `jit-grant` PRs.  The
approval action itself lives on the Forgejo PR page — no RHDH plugin is needed
for the approver to act.

**What this does NOT give you:** an inline approve/deny button inside RHDH.  That
requires a custom card plugin reading the Forgejo API and is out of scope for
Phase 2 MVP.

**mcp-server Resources (`catalog/pfsense.yaml`, `catalog/echo.yaml`):** these
already carry `spec.links` pointing at the live endpoint and the agentgateway
config.  Do not add a `jit-grant` link to those files — the JIT PR queue is
per-sandbox, not per-capability.  The JIT link belongs on the launched Sandbox
entity only.

### Launcher contract addendum

When the launcher emits the Sandbox `catalog-info.yaml`, it must substitute the
real sandbox name into the console URL and the correct numeric label ID into the
Forgejo URL's `labels=` parameter (Forgejo/Gitea accepts only numeric IDs here —
look up the ID once via `GET /api/v1/repos/anaeem/nvidia-ida/labels` and bake it
into the launcher template).

Using the global `jit-grant` label ID returns all open JIT PRs platform-wide,
which is correct for Phase 2 MVP (admins see all pending approvals in one view).
For a tighter per-sandbox filter, create a per-run label `jit-<sandbox-name>` in
Forgejo and use its numeric ID in the `labels=` param — at the cost of one extra
Forgejo API call per sandbox launch.

---

## 6. Verification checklist

```
# Plugin can see the CRD type at all:
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  get crd sandboxes.agents.x-k8s.io

# SA token can actually list sandboxes (impersonate to test RBAC):
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  auth can-i list sandboxes.agents.x-k8s.io \
  --as=system:serviceaccount:rhdh:developer-hub-kubernetes \
  -n agent-sandboxes

# A launched sandbox carries the matching label:
oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify \
  -n agent-sandboxes get sandboxes \
  -l backstage.io/kubernetes-id --show-labels
```

If the tab is empty: re-check (a) the `apiVersion` is version-only, (b) the SA
`can-i list` returns `yes`, and (c) the CR label exactly equals the entity's
`backstage.io/kubernetes-id` annotation value.
