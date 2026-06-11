# grafana-dashboards

## What
Two Grafana dashboard JSONs packaged as ConfigMaps with label `grafana_dashboard=1`.
Targets the existing Grafana instance at `http://172.16.2.252:3000`.

## Dashboards

### agentic-platform.json (uid: `agentic-platform-v1`)
Token/cost usage and platform health:
- **Token Usage by Model** — `agentic_claude_code_token_usage_total` by model/type
- **Cost per Agent Run** — `agentic_claude_code_cost_usage_total` in USD by session
- **MCP Call Latency** — `agentic_ext_proc_call_duration_seconds` histogram (p50/p95/p99) by tool
- **Tool Call Counts** — `agentic_ext_proc_tool_calls_total` top-20 by tool/user
- **AuthZ Denials Rate** — `agentic_agent_authz_denials_total` rate(5m) with red threshold
- **Error Rates** — `agentic_ext_proc_errors_total`, `agentic_mcp_tool_errors_total`
- **Token Usage by Session** — top-10 table

OTel metric names follow the Claude Code SDK convention:
- `claude_code.token.usage` → Prometheus: `agentic_claude_code_token_usage_total`
- `claude_code.cost.usage` → Prometheus: `agentic_claude_code_cost_usage_total`
  (The `agentic_` prefix comes from the OTel collector's `namespace: agentic` setting.)

### jit-audit.json (uid: `jit-audit-v1`)
JIT approval workflow and audit trail:
- **JIT Timeline** — requests/approvals/expiries rate
- **Active Grants Table** — current live grants with user/tool/namespace
- **Approval Latency** — histogram p50/p95 from request to grant
- **Audit Log panels** (Loki datasource):
  - `{app="ext-proc-delegation"} | json` — all ext-proc audit events
  - `{app="jit-approver"} | json` — JIT approver events
  - `{app="ext-proc-delegation"} | json | decision="deny"` — denials only

## Datasources required in Grafana
| Variable | Type | Target |
|---|---|---|
| `DS_PROMETHEUS` | Prometheus | UWM Thanos querier — `https://thanos-querier.openshift-monitoring.svc.cluster.local:9091` or the OCP console proxy |
| `DS_LOKI` | Loki | `http://172.16.2.252:3100` |

## Metric/log flow wiring diagram

```
Agent pods (agent-sandbox ns)
  │  OTLP gRPC :4317
  ▼
ext-proc-delegation (mcp-gateway ns)   ─── OTLP ──► otel-collector :4317
jit-approver (mcp-gateway ns)          ─── OTLP ──►    (agentic-observability ns)
pfsense-mcp (agentic-mcp ns)           ─── OTLP ──►         │
Claude Code SDK (any ns)               ─── OTLP ──►         │
                                                             │
                              ┌──────────────────────────────┤
                              │                              │
                              ▼                              ▼
                     Prometheus exporter             Loki exporter
                        :8889/metrics            endpoint: 172.16.2.252:3100
                              │                              │
                              ▼                              ▼
                  UWM ServiceMonitor scrape          Existing Loki
                  → UWM Prometheus              at 172.16.2.252:3100
                              │                              │
                              ▼                              ▼
                   PrometheusRule alerts           Grafana Loki datasource
                   → UWM Alertmanager               http://172.16.2.252:3000
                              │                              │
                              ▼                              └──► jit-audit panels
                   AlertmanagerConfig                             ext-proc log panels
                   eda=true → webhook
                   → AAP EDA Event Stream
                   → Ansible remediation
```

## Importing dashboards to Grafana

### Option A — Grafana sidecar (automatic)
If the Grafana instance has the dashboard sidecar configured
(`grafana.sidecar.dashboards.enabled: true` in Helm values), apply the
ConfigMaps to any namespace the sidecar watches and dashboards will auto-load.

Check if sidecar is running:
```bash
curl -s http://172.16.2.252:3000/api/health | jq .
```

### Option B — Manual import
1. Open `http://172.16.2.252:3000`.
2. Dashboards > Import > Upload JSON file.
3. Upload each JSON file (extract from the ConfigMap data field or use the raw
   JSON files from this repo).
4. Map `DS_PROMETHEUS` to your UWM Prometheus datasource.
5. Map `DS_LOKI` to a Loki datasource pointed at `http://172.16.2.252:3100`.

### Option C — Grafana API
```bash
GRAFANA=http://172.16.2.252:3000
TOKEN=<your-grafana-api-key>

# Extract JSON from ConfigMap and import
kubectl get cm grafana-dashboard-agentic-platform -n agentic-observability \
  -o jsonpath='{.data.agentic-platform\.json}' | \
  jq '{dashboard: ., overwrite: true, folderId: 0}' | \
  curl -s -X POST -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d @- "${GRAFANA}/api/dashboards/import"
```

## Apply order
This component can be applied after `user-workload-monitoring/` creates the
namespace. It does not depend on `otel-collector/` being running.
