# Session-Token Audit Logs — design & rollout plan

Status: **authored 2026-06-23** (not yet deployed — held while two sub-agents mutate the
cluster and etcd sits at ~2 GB). This is the plan to centralise + correlate the
session-token lifecycle audit trail into the existing observability stack.

## Why now
The zero-trust loop already *produces* a rich audit trail, but it lives in three
disconnected places (two stdout streams + one postgres WORM ledger). There is no single
place to answer "show me the full life of this elevation: who asked, who approved, what
scope, which token, was it used, was it burned." This plan wires that up.

## The three audit sources (all already emitting)
| Source | Transport | Key fields | Correlation key(s) |
|---|---|---|---|
| `approval-console` (`_audit`) | stdout JSON | `jit.approve`, `agent.session_created`, `agent.create/delete/archive`, `outcome`, `tool_args_hash`, actor | request id, agent_id, session_id |
| `jit-approver` | CNPG postgres (WORM) | `jit_session`(requester_sub, approver_sub, **scope_hash**, state), **`jit_ledger`** (hash-chained, INSERT/SELECT only — UPDATE/DELETE revoked), `consumed_jti` (single-use jti burn) | session id, **jti**, scope_hash |
| `ext-proc-delegation` | stdout slog JSON | `grant_result`(valid/expired/absent/nonce_mismatch/scope_denied/malformed), `decision`(allow/deny), `credential_injected`, `mcp_tool`, `caller_username` | **`session_id` + `jit_session_id`** |

**Lifecycle reconstruction** (the value): `console jit.approve` → `jit-approver mint`
(jti, scope_hash, approver_sub, WORM entry) → `ext-proc use` (grant_result=valid,
credential_injected, tool) → `consumed_jti` (burn). Joinable on **`jit_session_id`**
across the two log streams, and on **`jti`** into the WORM ledger.

## The sink (already exists, currently UNFED)
`agentic-observability/otel-collector`:
- Receivers: OTLP `:4317` (grpc) / `:4318` (http).
- Logs pipeline: `otlp → [batch, attributes/add_cluster, attributes/hash_tool_args,
  resource/loki_hints, attributes/loki_hints] → loki`.
- Exporters: `loki` (`LOKI_PUSH_URL=http://172.16.2.252:3100`), `prometheus` +
  `prometheusremotewrite` (`http://172.16.2.252:9090`).

**The gap:** `OTEL_EXPORTER_OTLP_ENDPOINT` is unset on all 5 services
(ext-proc, jit-approver, approval-console, mcp-gateway, sandbox-launcher), so nothing
reaches the collector. The pipeline (incl. the audit-aware `hash_tool_args` processor)
was built in anticipation but never fed.

## Two feed options
### A. App-level OTLP (target end-state — highest fidelity)
Add an OTLP log handler + `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.agentic-observability:4318`
to each service, emitting the audit events as structured OTLP log records (correlation IDs
as attributes, not regex-parsed). Pros: clean labels, no node-level scraping, survives log
rotation. Cons: code change in each service (Go ext-proc + Python jit-approver/console).
**Deferred** — those code surfaces are being edited by the in-flight sub-agents right now.

### B. Log-scrape via filelog receiver (interim — zero app change)
Add a `filelog` receiver to the collector (or a small DaemonSet collector) scraping the
mcp-gateway audit pods' stdout, parsing the JSON, promoting the session-token fields to
attributes, exporting to the same Loki pipeline. Pros: non-colliding, no app changes.
Cons: node-level file access, noisier, parse-fragile. Good bridge until (A) lands.

## WORM ledger (postgres) — surface, don't move
`jit_ledger` is the tamper-evident authoritative approval record (hash chain +
`jit_ledger_head`). Do NOT export it into Loki as the source of truth — instead add a
**Grafana postgres datasource** (read-only `app` role, SELECT on `jit_ledger`/`jit_session`)
and a dashboard panel that joins it to the Loki log stream by `session_id`/`jti`.

## Deliverables (this plan)
1. **Grafana dashboard** "Session-Token Lifecycle" — `observability/dashboards/session-token-audit.json`:
   - Table: per `jit_session_id` → requester, approver, scope_hash, state (from postgres).
   - Logs panel: ext-proc `grant_result`/`decision`/`credential_injected` filtered by `jit_session_id`.
   - Stat: tokens minted vs consumed (consumed_jti) vs denied (grant_result!=valid).
   - Alert: any `decision=allow` with `grant_result!=valid` (should be impossible — fail-open canary).
2. **otel filelog patch** (`observability/otel/filelog-audit-receiver.yaml`) — option B, held.
3. **App-OTLP rollout** (option A) — sequenced AFTER the sub-agents free jit-approver/console.

## Rollout sequencing (deliberate, given fragility)
1. Hold all cluster mutations until: (a) the two sub-agents finish, (b) etcd is defragged
   (snapshot first; it is ~2 GB vs the ~800 MB defrag threshold).
2. Apply option B (filelog) + the Grafana datasource + dashboard → verify a real
   elevation shows end-to-end in one view.
3. Land option A (app-level OTLP) per service as the durable end-state; retire B.
4. Add the fail-open canary alert.

## Open questions
- Is the Loki/Grafana at `172.16.2.252` retaining + indexing `jit_session_id` as a label
  (cardinality)? Confirm before promoting it to a Loki label vs a structured field.
- Does the WORM `app` role permit a read-only Grafana SELECT, or is a dedicated
  `audit_reader` role warranted (least privilege)?
