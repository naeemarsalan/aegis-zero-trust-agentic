# user-workload-monitoring

## What
Enables OpenShift User Workload Monitoring (UWM) on the anaeem cluster so that
PrometheusRules and ServiceMonitors in `agentic-observability` are picked up by
the platform Prometheus operator.

## Why
The agentic platform exposes custom metrics (authz denials, JIT grant counts,
MCP call latency histograms) via the OTel collector's Prometheus exporter. UWM
is the supported mechanism to scrape these on OCP without deploying a second
Prometheus instance.

## Resources created
| Resource | Namespace | Effect |
|---|---|---|
| `Namespace/agentic-observability` | — | Target namespace for all agentic observability resources |
| `ConfigMap/cluster-monitoring-config` | `openshift-monitoring` | **CLUSTER-WIDE** — enables `enableUserWorkload: true` |
| `ConfigMap/user-workload-monitoring-config` | `openshift-user-workload-monitoring` | Tunes UWM Prometheus retention/resources |

## WARNING — cluster-level changes
Both ConfigMaps **patch the cluster monitoring stack**. They are NOT namespaced
to `agentic-observability`. Applying them affects all user workload metrics on
the cluster. Coordinate with the cluster admin before applying on a shared
cluster.

The `openshift-user-workload-monitoring` namespace is **auto-created by OCP**
when `enableUserWorkload: true` is set. Do not create it manually.

## Apply order
1. Apply this component first (creates namespace + enables UWM).
2. Then apply `otel-collector/`, `alerts/`, `grafana-dashboards/`.

## Verify
```bash
# UWM Prometheus pods running
oc get pods -n openshift-user-workload-monitoring

# Namespace exists with monitoring label
oc get ns agentic-observability -o yaml | grep openshift.io/cluster-monitoring
```
