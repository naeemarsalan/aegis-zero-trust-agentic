# AAP EDA — Agent Remediation Integration

## What this does

Closes the self-healing loop for `AgentPermissionDenied` events:

```
AlertManager (anaeem cluster)
  │  Alertmanager webhook POST
  ▼
AAP 2.6 Event Stream "agent-denials"   (hammer cluster)
  │  forward_events: true
  ▼
EDA Rulebook Activation "agent-remediation-activation"
  │  rules: event.payload.alerts[0].labels.alertname == "AgentPermissionDenied"
  ▼
run_job_template: "Agent Remediation PR"
  │  extra_vars: namespace, tool, user, denial_reason, raw_alert_payload
  ▼
Ansible Playbook (job-templates/remediation-pr.yml)
  │
  ├─ Query Loki (LogQL) — last 50 denial log lines
  ├─ Generate RBAC Role+RoleBinding  OR  Kyverno PolicyException YAML
  ├─ Gitea API: create branch  eda/remediation-<ts>
  ├─ Gitea API: commit remediations/<ts>-<ns>-<user>.yaml  +  loki log file
  ├─ Gitea API: open PR  (title, full log body, "remediation" label)
  └─ Gitea API: open cross-reference issue  (PR link mention)
       │
       ▼
  Human reviews PR on Gitea (https://git.arsalan.io)
       │  PR MERGE = JIT approval
       ▼
  jit-approver webhook (mcp-gateway) records approval in audit log
```

**No Slack anywhere.** The Gitea PR and issue are the notification channel.
PR merge is the human-in-the-loop approval signal (same pattern as UC-2).

---

## Component map

```
integrations/eda-aap/
├── rulebooks/
│   └── agent-remediation.yml      # EDA rulebook; webhook source = local-dev fallback only
├── job-templates/
│   └── remediation-pr.yml         # Ansible playbook: Loki query + PR generation
├── event-streams/
│   ├── agent-denials.yml          # Event Stream desired-state spec + docs
│   └── controller-credential.yml  # AAP controller back-channel credential spec
├── decision-environment/
│   ├── de.yml                     # ansible-builder definition (custom DE; default DE suffices)
│   └── README.md                  # When to build a custom DE
├── setup.sh                       # Idempotent bootstrap via AAP REST API
└── README.md                      # This file
```

---

## Prerequisites

| Item | Value |
|------|-------|
| AAP version | 2.6 (gateway API, EDA 2.x) |
| AAP hostname | `https://aap-aap.apps.hammer.na-launch.com` |
| Gitea | `https://git.arsalan.io` repo `anaeem/nvidia-ida` |
| Loki | `http://172.16.2.252:3100` |
| `environment/.env` | Populated (see below) |

### Required env vars in `environment/.env`

```bash
AAP_HOSTNAME=https://aap-aap.apps.hammer.na-launch.com
AAP_CONTROLLER_USERNAME=admin
AAP_CONTROLLER_PASSWORD=<controller password>
GITEA_URL=https://git.arsalan.io
GITEA_TOKEN=<personal access token — repo write scope>
GITEA_REPO_OWNER=anaeem
GITEA_REPO_NAME=nvidia-ida
LOKI_PUSH_URL=http://172.16.2.252:3100
AAP_EDA_STREAM_TOKEN=<random secret — used as Bearer token for the Event Stream inbound webhook>
```

Generate a stream token: `openssl rand -hex 32`

---

## Bootstrap

```bash
# 1. Fill in environment/.env (never commit it)
cp environment/.env.example environment/.env
$EDITOR environment/.env

# 2. Run setup (idempotent — safe to re-run)
bash integrations/eda-aap/setup.sh
```

The script prints the **Event Stream ingress URL** at the end.  Copy it.

---

## Wire up AlertManager

Add a receiver to the AlertmanagerConfig in `platform/agentic-observability`
(or wherever your PrometheusRule/AlertManager config lives):

```yaml
# platform/agentic-observability/base/alertmanager-config.yaml  (excerpt)
apiVersion: monitoring.coreos.com/v1beta1
kind: AlertmanagerConfig
metadata:
  name: eda-agent-denials
  namespace: agentic-observability
spec:
  route:
    receiver: eda-agent-denials
    matchers:
      - name: alertname
        value: AgentPermissionDenied
  receivers:
    - name: eda-agent-denials
      webhookConfigs:
        - url: '<EVENT STREAM INGRESS URL from setup.sh>'
          httpConfig:
            authorization:
              type: Bearer
              credentials:
                name: eda-stream-token
                key: token
          sendResolved: false
```

Create the secret (namespace `agentic-observability`, key `token`):

```bash
kubectl -n agentic-observability create secret generic eda-stream-token \
  --from-literal=token="${AAP_EDA_STREAM_TOKEN}"
```

---

## AAP 2.6 specifics

### Gateway API vs component APIs

AAP 2.6 exposes a unified gateway at `https://aap-aap.apps.hammer.na-launch.com`.
Sub-APIs:

| Sub-system | Path prefix |
|-----------|-------------|
| Controller (job templates, projects, credentials) | `/api/controller/v2/` |
| EDA (activations, event streams, projects, credentials) | `/api/eda/v1/` |
| Gateway (users, orgs, shared resources) | `/api/gateway/v1/` |

`setup.sh` uses all three as needed.

### Token credential deprecation

AAP 2.5 deprecated token-based controller credentials; AAP 2.6 removes them.
The EDA -> Controller back-channel credential (`aap-controller-for-eda`) uses
credential type **"Red Hat Ansible Automation Platform"** with
`username` + `password` inputs, not a token.

### Event Stream vs webhook source

In the rulebook `sources:` block, `ansible.eda.webhook` is present as a
**local-dev fallback only**.  When the activation is backed by an Event Stream
(production), the EDA engine injects the stream as the source automatically —
no `sources:` block is required.  Do **not** use both simultaneously.

---

## Verify steps

### 1. Check activation status

```bash
curl -s -k \
  -u "${AAP_CONTROLLER_USERNAME}:${AAP_CONTROLLER_PASSWORD}" \
  "https://aap-aap.apps.hammer.na-launch.com/api/eda/v1/activations/" \
  | python3 -m json.tool | grep -A5 '"name": "agent-remediation-activation"'
```

Expected: `"status": "running"`

### 2. Check event stream

```bash
curl -s -k \
  -u "${AAP_CONTROLLER_USERNAME}:${AAP_CONTROLLER_PASSWORD}" \
  "https://aap-aap.apps.hammer.na-launch.com/api/eda/v1/event-streams/" \
  | python3 -m json.tool | grep -A10 '"name": "agent-denials"'
```

### 3. Send a synthetic alert

```bash
source environment/.env
curl -X POST "${EVENT_STREAM_URL}" \
  -H "Authorization: Bearer ${AAP_EDA_STREAM_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "alerts": [{
      "labels": {
        "alertname": "AgentPermissionDenied",
        "namespace":    "agent-sandbox",
        "tool":         "pfsense-mcp",
        "user":         "test@example.com",
        "denial_reason": "kyverno policy block test"
      },
      "annotations": {
        "summary":     "Test alert — EDA loop verification",
        "description": "Synthetic event to verify the full EDA -> PR loop."
      }
    }]
  }'
```

### 4. Verify in AAP

- Controller > Jobs > "Agent Remediation PR" — should appear as running/complete.
- EDA > Rulebook Activations > "agent-remediation-activation" > History.

### 5. Verify in Gitea

- `https://git.arsalan.io/anaeem/nvidia-ida/pulls` — PR with label `remediation` should appear.
- PR body should contain Loki log lines.
- Branch: `eda/remediation-<ts>`.

---

## Credential env var reference

| Env var | Used by | Notes |
|---------|---------|-------|
| `AAP_HOSTNAME` | setup.sh | Full URL with `https://` |
| `AAP_CONTROLLER_USERNAME` | setup.sh, EDA credential | Service account preferred |
| `AAP_CONTROLLER_PASSWORD` | setup.sh, EDA credential | |
| `GITEA_URL` | setup.sh, playbook | Full URL |
| `GITEA_TOKEN` | setup.sh, playbook | Injected as `GITEA_TOKEN` env in JT |
| `GITEA_REPO_OWNER` | setup.sh, playbook | |
| `GITEA_REPO_NAME` | setup.sh, playbook | |
| `LOKI_PUSH_URL` | setup.sh, playbook | Injected as `LOKI_PUSH_URL` env in JT |
| `AAP_EDA_STREAM_TOKEN` | setup.sh, AlertManager | Bearer token for inbound Event Stream auth |

All values live in `environment/.env` (gitignored).  None are ever inlined in
YAML, playbooks, or committed to git.
