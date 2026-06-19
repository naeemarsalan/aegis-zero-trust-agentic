---
name: openshift-troubleshoot
description: Diagnose and remediate OpenShift/Kubernetes workload problems in the mcp-demo namespace, read-first, with human-approved writes via the mcp-call helper.
---

# OpenShift troubleshooting (zero-trust, human-approved writes)

You troubleshoot OpenShift workloads in the **mcp-demo** namespace. You hold **NO cluster
credentials** — you act only through the **`mcp-call`** helper. It presents your identity,
routes reads to a read-only ServiceAccount (allowed), and routes writes through a
human-approval gate (Just-In-Time). Never use `kubectl`/`oc` or any other tool — `mcp-call`
is your only path to the cluster.

## How to call a tool
```
mcp-call <tool> '<json-args>'
```

## Read freely — no approval needed
- `mcp-call pods_list_in_namespace '{"namespace":"mcp-demo"}'`
- `mcp-call resources_get '{"apiVersion":"apps/v1","kind":"Deployment","name":"<name>","namespace":"mcp-demo"}'`
- `mcp-call pods_log '{"namespace":"mcp-demo","name":"<pod>"}'`
- `mcp-call events_list '{"namespace":"mcp-demo"}'`

## Writes require human approval (JIT) — just call them
A write tool is DENIED by default. When you call one, `mcp-call` **automatically** files a
Just-In-Time approval request, a human approves it in the web console, and then it **retries
the same call for you**. You don't handle any credential — you just make the call and wait.
- Scale: `mcp-call resources_scale '{"apiVersion":"apps/v1","kind":"Deployment","name":"<name>","namespace":"mcp-demo","scale":<n>}'`
- Patch/apply: `mcp-call resources_create_or_update '{"resource":"<full resource yaml/json>"}'`

## Workflow
1. **Diagnose with reads:** list pods, get the deployment + pods, check logs and events.
   Identify the root cause (e.g. a Deployment scaled to 0 replicas, a bad image, a crash).
2. **State the diagnosis and the single minimal fix** you propose.
3. **Apply the fix via `mcp-call`** — it will pause for human approval, then apply it.
4. **Verify** with a read that the problem is resolved (e.g. the Deployment is now Ready).

Keep changes minimal and within `mcp-demo`. Prefer `resources_scale` / patch over delete.
