# alerts

## What
PrometheusRule and AlertmanagerConfig for the agentic platform in namespace
`agentic-observability`. Alerts are routed to AAP EDA Event Streams for
automated remediation.

## Why
- **AgentPermissionDenied**: fires when `ext-proc-delegation` records an AuthZ
  denial. EDA rulebooks can trigger Ansible playbooks to revoke grants, notify
  teams, or open Gitea issues.
- **JITGrantIssued**: informational; lets EDA track the full JIT approval
  workflow from request to grant to expiry.
- **OtelCollectorDown**: operational; ensures observability gaps are detected.

## Resources
| Resource | Type | Description |
|---|---|---|
| `agentic-platform-alerts` | PrometheusRule | Alert definitions |
| `agentic-eda-routing` | AlertmanagerConfig | Routes `eda=true` alerts to AAP EDA webhook |
| `eda-webhook-creds` | Secret | Bearer token placeholder — must be populated |

## Setting up AAP EDA Event Streams (prerequisite)

1. Log in to AAP at `https://aap-aap.apps.hammer.na-launch.com`.
2. Navigate to **Event Driven Automation > Event Streams > Create Event Stream**.
3. Name: `agentic-platform-alerts`, Type: `Alertmanager`.
4. Copy the UUID from the Event Stream detail URL.
5. Edit `overlays/anaeem/patch-eda-url.yaml` — replace `<EVENT-STREAM-UUID>`.
6. Copy the bearer token shown in the Event Stream detail.
7. Create the webhook secret (see below).

## Populating the webhook secret

**Option A — manual (dev only):**
```bash
oc create secret generic eda-webhook-creds \
  --from-literal=bearer-token=<TOKEN_FROM_AAP_EDA> \
  -n agentic-observability \
  --dry-run=client -o yaml | oc apply -f -
```

**Option B — ExternalSecret from Vault (production):**
Store the token at `secret/agentic-observability/eda-webhook-creds` in Vault,
then replace `base/eda-webhook-secret.yaml` with an ExternalSecret CR
referencing the Vault path. See `platform/vault/` for the Vault setup.

## Alert label schema
| Label | Values | Meaning |
|---|---|---|
| `severity` | warning, info, critical | Paging priority |
| `eda` | true | Routes to EDA Event Stream webhook |
| `team` | platform | Owning team |
| `namespace` | string | K8s namespace of the denied/granted agent |
| `tool` | string | MCP tool name (hashed in Loki, raw in Prometheus labels) |
| `user` | string | Agent/user identity |

## Apply order
1. `user-workload-monitoring/` — UWM must be enabled first.
2. `otel-collector/` — ServiceMonitor must exist for UWM to discover the job.
3. This component (`alerts/`).

## Verify
```bash
# PrometheusRule picked up by UWM
oc get prometheusrule -n agentic-observability

# AlertmanagerConfig (check status for any errors)
oc get alertmanagerconfig -n agentic-observability -o yaml

# Simulate an alert — fire via amtool or Alertmanager API
# Get UWM Alertmanager route
AMROUTE=$(oc get route -n openshift-user-workload-monitoring alertmanager-user-workload -o jsonpath='{.spec.host}')
curl -s "https://${AMROUTE}/api/v2/status" | jq .config.original | head -30
```
