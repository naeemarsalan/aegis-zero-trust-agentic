# otel-collector

## What
Plain Deployment of `opentelemetry-collector-contrib:0.102.0` in namespace
`agentic-observability`. No OTel operator is present on the anaeem cluster —
this uses a standard Kubernetes Deployment.

## Why
Central telemetry hub for the agentic platform:
- Receives OTLP (gRPC :4317, HTTP :4318) from agent pods, ext-proc-delegation,
  jit-approver, pfsense-mcp, and Claude Code SDK instrumentation.
- Adds `cluster=anaeem` attribute to every signal.
- **Hashes** `tool_args` and `tool_input` before forwarding (security invariant:
  raw tool arguments must never appear in audit logs).
- Exports metrics via Prometheus exporter (:8889) scraped by UWM (primary).
- Exports metrics via `prometheusremotewrite` to the existing Prometheus at
  `http://172.16.2.252:9090` (secondary, enabled by `PROMETHEUS_REMOTE_WRITE_URL` env var).
- Exports logs and traces-as-logs to Loki at `LOKI_PUSH_URL`.

## Pipelines

| Signal | Receivers | Processors | Exporters |
|---|---|---|---|
| traces | otlp | batch, add_cluster, hash_tool_args | loki (as logs), debug |
| metrics | otlp | batch, add_cluster | prometheus (:8889) + prometheusremotewrite |
| logs | otlp | batch, add_cluster, hash_tool_args | loki |

## Configuration

Two env vars are set on the Deployment container by the anaeem overlay
(`overlays/anaeem/patch-loki-url.yaml`):

| Env var | Value (anaeem) | Purpose |
|---|---|---|
| `LOKI_PUSH_URL` | `http://172.16.2.252:3100` | Loki push endpoint (primary logs/traces sink) |
| `PROMETHEUS_REMOTE_WRITE_URL` | `http://172.16.2.252:9090/api/v1/write` | Existing Prometheus remote-write endpoint |

### Prometheus remote-write detail

The `prometheusremotewrite` exporter is declared in the base configmap and always
included in the metrics pipeline.  It forwards agent token/cost/latency metrics to the
existing Prometheus instance at `http://172.16.2.252:9090` so that existing Grafana
dashboards on that host also receive the agentic platform metrics.

This is **additive** — the primary UWM-scraped Prometheus exporter on `:8889` is
unaffected.  Both exporters receive the same metrics pipeline output.

To disable remote-write (e.g. in another overlay), set:
```yaml
- name: PROMETHEUS_REMOTE_WRITE_URL
  value: ""
```
An empty URL causes the `prometheusremotewrite` exporter to fail on startup; to
fully disable it for a non-anaeem overlay, remove it from the metrics pipeline
exporters list in a configmap patch.

### Loki push
Loki push stays `http://172.16.2.252:3100` (matching `environment/clusters.yaml`
`observability.lokiPush`).

## Apply order
1. `user-workload-monitoring/` must be applied first (namespace creation + UWM).
2. Apply this component.
3. Then apply `alerts/` (ServiceMonitor must exist before PrometheusRules are validated).

## Verify
```bash
# Collector pod running
oc get pods -n agentic-observability -l app=otel-collector

# Metrics endpoint responding (primary UWM target)
oc port-forward -n agentic-observability svc/otel-collector 8889:8889 &
curl -s http://localhost:8889/metrics | grep agentic_

# UWM scraping — check targets in console
# Console -> Observe -> Targets -> filter by namespace agentic-observability

# Confirm PROMETHEUS_REMOTE_WRITE_URL is set in the running pod
oc -n agentic-observability exec deploy/otel-collector -- \
  env | grep PROMETHEUS_REMOTE_WRITE_URL
# -> PROMETHEUS_REMOTE_WRITE_URL=http://172.16.2.252:9090/api/v1/write

# Send a test OTLP log
grpcurl -plaintext -d '{}' localhost:4317 opentelemetry.proto.collector.logs.v1.LogsService/Export
```

## Image update procedure
Pin image digest with skopeo:
```bash
skopeo inspect docker://ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.102.0 \
  | jq .Digest
# Then update base/deployment.yaml image field with @sha256:<digest>
```
