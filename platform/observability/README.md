# platform/observability

## What
Full observability stack for the agentic platform on the `anaeem` cluster
(namespace `agentic-observability`). Wires OTel telemetry from agent pods,
ext-proc-delegation, jit-approver, and Claude Code SDK sessions to the existing
Grafana/Loki stack at `172.16.2.252` and to OpenShift User Workload Monitoring.

## Components

| Component | What it does |
|---|---|
| `user-workload-monitoring/` | Enables UWM on the cluster; creates `agentic-observability` namespace |
| `otel-collector/` | Plain Deployment of OTel contrib collector; receives OTLP, exports to Prometheus+Loki |
| `alerts/` | PrometheusRules + AlertmanagerConfig routing `eda=true` alerts to AAP EDA |
| `grafana-dashboards/` | Two dashboard ConfigMaps (agentic-platform + jit-audit) |

## Metric/log flow

```
Agent pods ──OTLP──► otel-collector ──prometheus exporter :8889──► UWM Prometheus ──► PrometheusRules
                                    ──loki exporter──────────────► Loki 172.16.2.252:3100 ──► Grafana
                                                                                 UWM Alertmanager ──► AAP EDA
```

## Apply order (IMPORTANT)

Apply components in this order:

```bash
# 1. Enable UWM + create namespace (CLUSTER-WIDE change — coordinate with admin)
kustomize build platform/observability/user-workload-monitoring/overlays/anaeem | oc apply -f -

# Wait for UWM pods to be ready
oc wait -n openshift-user-workload-monitoring pod --all --for=condition=Ready --timeout=120s

# 2. Deploy OTel collector
kustomize build platform/observability/otel-collector/overlays/anaeem | oc apply -f -

# 3. Apply alerts (BEFORE this: populate eda-webhook-creds secret + update EDA UUID in patch)
kustomize build platform/observability/alerts/overlays/anaeem | oc apply -f -

# 4. Apply Grafana dashboards
kustomize build platform/observability/grafana-dashboards/overlays/anaeem | oc apply -f -
```

## Pre-apply checklist

- [ ] Confirm `openshift-user-workload-monitoring` namespace does NOT already exist
      (it is auto-created by OCP when UWM is enabled)
- [ ] Create AAP EDA Event Stream and obtain UUID — update
      `alerts/overlays/anaeem/patch-eda-url.yaml`
- [ ] Populate `eda-webhook-creds` Secret with bearer token from AAP EDA
      (see `alerts/README.md`)
- [ ] Confirm Loki push URL: `curl http://172.16.2.252:3100/ready`
      (update `otel-collector/overlays/anaeem/patch-loki-url.yaml` if different)
- [ ] Confirm Grafana at `http://172.16.2.252:3000` is reachable from cluster
      (egress from otel-collector pod to 172.16.2.252)

## Security invariants maintained

- Tool arguments (`tool_args`, `tool_input`) are **hashed** (SHA-256) by the
  OTel collector's `attributes/hash_tool_args` processor before forwarding to
  Loki. Raw tool inputs never appear in audit logs.
- The `eda-webhook-creds` Secret must be populated via Vault Agent Injector or
  ExternalSecret in production — the base contains only a placeholder.
- Default-deny NetworkPolicy on the OTel collector pod. Egress to Loki is
  permitted via the `NetworkPolicy` (no Ingress restriction on egress by default).

## Verify end-to-end

```bash
# 1. OTel collector healthy
oc get pods -n agentic-observability -l app=otel-collector

# 2. UWM scraping the collector (check in OCP console: Observe > Targets)
oc get servicemonitor -n agentic-observability

# 3. PrometheusRule loaded
oc get prometheusrule -n agentic-observability

# 4. AlertmanagerConfig loaded
oc get alertmanagerconfig -n agentic-observability

# 5. Send a test OTLP metric from within the cluster
oc run otlp-test --rm -it --image=curlimages/curl --restart=Never -- \
  curl -s http://otel-collector.agentic-observability.svc.cluster.local:4318/v1/metrics \
  -H "Content-Type: application/json" -d '{"resourceMetrics": []}'

# 6. Check Loki for logs from ext-proc-delegation
# LogQL: {app="ext-proc-delegation"} | json
```
