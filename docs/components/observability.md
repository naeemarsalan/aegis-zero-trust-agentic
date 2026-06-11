## Purpose

The observability stack provides unified metrics, logs, and alerting for all platform components and AI agent workloads. It collects OpenTelemetry traces and metrics from agentgateway, ext-proc-delegation, and agent pods; ships logs (with tool arguments SHA-256 hashed) to an external Loki instance; and exposes dashboards in an existing Grafana instance. Alertmanager rules feed the EDA-AAP remediation loop.

## Exists or create

CREATE on anaeem — deploy an OpenTelemetry Collector and Alertmanager in namespace `agentic-observability`. The external Grafana (`http://172.16.2.252:3000`) and Loki push endpoint (`http://172.16.2.252:3100`) already exist and are parameterized as `GRAFANA_URL` and `LOKI_PUSH_URL` in the kustomize overlay. No new Grafana or Loki instance is deployed on the cluster. KEDA is already installed on anaeem and can be used for autoscaling based on Prometheus metrics if needed.

## Placement

- Cluster: **anaeem** (SNO, OCP 4.20.11)
- Namespace: `agentic-observability`
- OTel Collector: `otel-collector.agentic-observability.svc.cluster.local:4317` (gRPC OTLP) and `:4318` (HTTP OTLP)
- Alertmanager: `alertmanager.agentic-observability.svc.cluster.local:9093`
- External Grafana: `http://172.16.2.252:3000` (parameterized, not modified)
- External Loki push: `http://172.16.2.252:3100` (parameterized as `LOKI_PUSH_URL`)
- No OCP Routes needed for OTel Collector or Alertmanager (internal push model)

## Security posture

- SPIFFE ID: `spiffe://anaeem.na-launch.com/ns/agentic-observability/sa/otel-collector`
- **Audit invariant**: tool arguments in all log lines are SHA-256 hashed before shipment to Loki; the OTel Collector processor pipeline contains a Transform processor that replaces `tool_args` attribute values with `sha256:<hex>`; raw arguments are never written to any log sink
- Vault Agent Injector injects any credentials needed for external Loki auth (if Loki requires a token) via tmpfs; no credentials in ConfigMaps
- NetworkPolicy: ingress on 4317/4318 from `mcp-gateway`, `agentic-mcp`, `agent-sandbox`, `keycloak`, `vault` namespaces; ingress on 9093 from `mcp-gateway` (Alertmanager webhook); egress to Loki push (`172.16.2.252:3100`) and Grafana (`172.16.2.252:3000`); deny all other ingress
- Fail-mode: if OTel Collector is unavailable, platform components use buffered export with retry; if buffer exhausts, spans are dropped (observability is non-critical-path — fail-open for the data plane, but an alert fires)

## Interfaces

| Peer | Direction | Port / Protocol | Purpose |
|------|-----------|-----------------|---------|
| agentgateway / ext-proc-delegation | outbound → OTel Collector | 4317 gRPC | OTLP traces + metrics |
| All platform pods | outbound → OTel Collector | 4318 HTTP | OTLP logs |
| OTel Collector | outbound → Loki | 3100 HTTP | Log forwarding (hashed args) |
| OTel Collector | outbound → Grafana / Prometheus | 3000 / 9090 HTTP | Metrics remote write |
| Alertmanager | outbound → EDA | 443 HTTPS | Alert webhook to EDA Event Stream |
| Alertmanager | outbound → Gitea | 443 HTTPS | Optional: incident issue creation |

## Maturity flags

- OpenTelemetry Collector (contrib distribution) is GA; the OTel Operator for OCP is available but we deploy the collector as a standalone Deployment for simplicity
- Loki push endpoint port 3100 is marked "TODO confirm" in clusters.yaml — verify with the Loki admin before applying; the OTel Collector's `loki` exporter supports both 3100 (Loki native) and Grafana Agent's port
- KEDA (already installed) can scale agent pods based on queue depth metrics from the OTel pipeline if needed

## Verify

```bash
# 1. Check OTel Collector pod is Running
oc get pods -n agentic-observability -l app=otel-collector

# 2. Confirm logs reach Loki (query recent entries from agentgateway)
curl -s "http://172.16.2.252:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={namespace="mcp-gateway"}' \
  --data-urlencode 'start=1h' | jq '.data.result | length'

# 3. Verify tool_args are hashed in a sample log line (must NOT contain raw JSON tool arguments)
curl -s "http://172.16.2.252:3100/loki/api/v1/query" \
  --data-urlencode 'query={app="agentgateway"} |= "tool_args"' \
  | jq '.data.result[0].values[-1][1]' | grep "sha256:"
```
