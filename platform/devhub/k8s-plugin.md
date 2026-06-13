# RHDH Kubernetes plugin — surfacing the Sandbox CR and JIT grants on an entity page

This document describes the configuration that lets a Red Hat Developer Hub
(RHDH) **entity page** show the live OpenShell `Sandbox` custom resource a user
launched (via the *Run an Agent* template) plus any JIT privilege-grant objects
tied to it — directly on the **Kubernetes** tab of the entity.

> All snippets below are **operator wiring**. They must be **merged by hand**
> into the live config on the `anaeem` cluster. Do **not** apply them
> automatically and do **not** edit the live RHDH ConfigMaps from a pipeline.
>
> Drive the cluster with:
> ```
> oc --kubeconfig=$HOME/.kube/anaeem-kubeconfig --insecure-skip-tls-verify ...
> ```

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
          url: https://api.anaeem.na-launch.com:6443
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

The Kubernetes tab matches resources by **label selector** derived from entity
annotations. The catalog entity representing the sandbox (the transient
`catalog-info.yaml` the launcher emits, or a static Component for the OpenShell
system) must carry:

```yaml
metadata:
  annotations:
    backstage.io/kubernetes-id: <sandbox-name>
    backstage.io/kubernetes-namespace: agent-sandboxes
```

`backstage.io/kubernetes-id` is the value the plugin uses to build the
`backstage.io/kubernetes-id=<sandbox-name>` label selector. Setting
`backstage.io/kubernetes-namespace` scopes the lookup to `agent-sandboxes` so
the plugin doesn't fan out cluster-wide.

You can also surface workloads by a custom label query instead of the id:

```yaml
metadata:
  annotations:
    backstage.io/kubernetes-label-selector: "agentic.io/sandbox=<sandbox-name>"
```

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
