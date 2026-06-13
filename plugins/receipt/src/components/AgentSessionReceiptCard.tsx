/**
 * AgentSessionReceiptCard — SKELETON
 *
 * mountPoint:  entity.page.overview/cards
 *
 * Condition:   isKind: resource  AND  isType: agent-sandbox
 *
 * Shows what the agent did (allowed tool calls) and what was denied during a
 * completed JIT session. Renders as a summary card on the entity Overview tab
 * alongside the existing Links and About cards.
 *
 * ─── REAL DATA SOURCES ────────────────────────────────────────────────────
 *
 * 1. SessionSummary (actions_taken, errors_encountered, outcome)
 *    Source:    Agent POSTs to POST /requests/{session_id}/summary
 *               (services/jit-approver/src/jit_approver/api.py:post_summary)
 *    Fields:    outcome: str, actions_taken: list[str], errors_encountered: list[str]
 *               Defined in models.py:SessionSummary.
 *    Storage:   Stored in session_store[session_id] as session["summary"] — BUT
 *               the current api.py:post_summary() does NOT write it back into the
 *               store dict; it only emits an audit event and posts a PR comment.
 *    MISSING:   GET /requests/{session_id}/summary — does not exist.
 *               The only record of the summary after posting is:
 *                 a) The Loki audit event (event=jit_summary, app=jit-approver)
 *                 b) The Gitea PR comment posted by post_summary()
 *
 *    TODO-C1 (jit-approver api.py + store.py):
 *      a) In post_summary(): add  session["summary"] = summary  after the
 *         audit.emit_summary() call, so the data survives for GET queries.
 *      b) Add GET /requests/{session_id}/summary endpoint that returns the
 *         stored SessionSummary, or 404 if the agent has not posted one yet.
 *      c) Add  summary: SessionSummary | None  field to SessionStatus Pydantic
 *         model (models.py) — then the existing GET /status endpoint can
 *         optionally include it without a new endpoint.
 *
 * 2. ext-proc denial events (decision="deny" from ext-proc-delegation)
 *    Source:    Loki at http://172.16.2.252:3100/loki/api/v1/query_range
 *    LogQL:     {app="ext-proc-delegation", cluster="anaeem"} | json | decision="deny"
 *    Fields:    mcp.tool, reason, caller_user.preferred_username, ts
 *    Denial reasons confirmed in server.go:
 *               no_identity | empty_body | body_too_large | mcp_parse_error |
 *               restricted_group | dangerous_requires_admin |
 *               dangerous_requires_jit_session | tool_not_in_jit_scope |
 *               exchange_failed | vault_failed | empty_downstream_token |
 *               no_delegation | static_token_fetch_failed | no_user_token
 *    MISSING:   172.16.2.252:3100 is a homelab IP not reachable from a browser
 *               without a CORS-enabled proxy. The RHDH proxy does not have a
 *               /loki entry today.
 *
 *    TODO-C2 (jit-approver — new endpoint OR new proxy entry):
 *      Option A (preferred): Add GET /requests/{session_id}/receipt to
 *        jit-approver that internally queries Loki and returns a pre-shaped:
 *        {
 *          allowed: int,
 *          denied: int,
 *          tool_calls: [{tool, decision, reason?, ts}],
 *          session_outcome: str,
 *          expires_at: str | null
 *        }
 *        This avoids the frontend needing direct Loki access.
 *      Option B: Add a /loki-query proxy entry to developer-hub-app-config
 *        pointing at http://172.16.2.252:3100 and query LogQL from the frontend.
 *        This exposes Loki to all RHDH users — use Option A for PoC.
 *
 * 3. Kube-audit attribution (SA token used correctly)
 *    Source:    oc adm node-logs --role=master --path=kube-apiserver/audit.log
 *               | grep 'jit-<session_id>'
 *    Status:    NOT reachable via any REST API the frontend can call.
 *    TODO-C3:   Stub as a documented TODO on the receipt card for Phase-3 PoC.
 *               The ext-proc logs (credential_injected=true events) are the
 *               auditable substitute visible in the existing Grafana dashboard.
 *
 * 4. Session state and pr_url
 *    Source:    GET /api/proxy/jit-approver/requests/{session_id}/status
 *    Status:    REAL — endpoint exists (api.py:get_status()).
 *    Requires:  /jit-approver proxy entry in developer-hub-app-config
 *               (platform/devhub/app-config-jit.yaml — TODO file).
 *
 * ─── MVP SCOPE FOR PHASE-3 POC ────────────────────────────────────────────
 *
 * For Phase-3 demo, restrict the receipt to:
 *   - actions_taken / errors_encountered from TODO-C1 GET /summary
 *   - session state badge from GET /status (real)
 *   - pr_url link (real)
 *   - "Denials from ext-proc: see Grafana dashboard" placeholder (honest)
 *   - No kube-audit section (honest TODO-C3 note)
 *
 * ─── BUILD STEPS ──────────────────────────────────────────────────────────
 *
 *   cd plugins/receipt
 *   yarn install
 *   npx @red-hat-developer-hub/cli@1.9.0 plugin export \
 *     --no-generate-module-federation-assets --clean
 *   cd dist-dynamic && npm pack
 *   HASH=$(npm pack --json | jq -r '.[0].integrity')
 *   # Upload tgz to https://git.arsalan.io and note the attachment URL.
 *
 * ─── CONFIGMAP DELTA (developer-hub-dynamic-plugins) ──────────────────────
 *
 *   plugins:
 *     - disabled: false
 *       package: https://git.arsalan.io/attachments/<uuid>.tgz
 *       integrity: sha512-<HASH>
 *       pluginConfig:
 *         dynamicPlugins:
 *           frontend:
 *             nvidia-ida.plugin-receipt:
 *               mountPoints:
 *                 - mountPoint: entity.page.overview/cards
 *                   importName: AgentSessionReceiptCard
 *                   config:
 *                     layout:
 *                       gridColumnEnd: span 12
 *                     if:
 *                       allOf:
 *                         - isKind: resource
 *                         - isType: agent-sandbox
 *
 * NOTE: No new entityTab needed — this card mounts on the EXISTING Overview tab
 * (entity.page.overview/cards), the same mountPoint used by the live
 * migration-discovery plugin. The `if` condition gates it to agent-sandbox only.
 */

import React, { useEffect, useState } from 'react';
import { InfoCard, EmptyState } from '@backstage/core-components';
import { useEntity } from '@backstage/plugin-catalog-react';
import { useApi, discoveryApiRef, fetchApiRef } from '@backstage/core-plugin-api';

// ---------------------------------------------------------------------------
// Types — mirrors services/jit-approver/src/jit_approver/models.py
// ---------------------------------------------------------------------------

type SessionState = 'pending' | 'approved' | 'issued' | 'expired' | 'denied';

interface SessionStatus {
  id: string;
  state: SessionState;
  pr_url: string | null;
  expires_at: string | null;
}

interface SessionSummary {
  outcome: string;
  actions_taken: string[];
  errors_encountered: string[];
}

// ---------------------------------------------------------------------------
// TtlCountdownChip — inline live countdown.
//
// This is a local copy of the setInterval-based logic from
// plugins/plan-consent/src/components/TtlCountdownChip.tsx.  It is inlined
// here because @nvidia-ida/plugin-plan-consent is not yet published to an npm
// registry reachable by this plugin's build.
//
// TODO: once @nvidia-ida/plugin-plan-consent is published, replace this block
// with:
//   import { TtlCountdownChip } from '@nvidia-ida/plugin-plan-consent';
// and add the package to dependencies in package.json.
//
// The countdown DOES tick (setInterval, 1 s); it is functionally equivalent
// to the plan-consent implementation for the expiresAt-driven path used here.
// ---------------------------------------------------------------------------

function _rcptFormatMmSs(totalSeconds: number): string {
  const clamped = Math.max(0, Math.floor(totalSeconds));
  const m = Math.floor(clamped / 60);
  const s = clamped % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

function _rcptSecsLeft(expiresAt: string): number {
  return (new Date(expiresAt).getTime() - Date.now()) / 1000;
}

const TtlCountdownChip = ({ expiresAt, label = 'session' }: { expiresAt: string | null; label?: string }) => {
  const [secsLeft, setSecsLeft] = useState<number | null>(
    () => (expiresAt ? _rcptSecsLeft(expiresAt) : null),
  );

  useEffect(() => {
    if (expiresAt) setSecsLeft(_rcptSecsLeft(expiresAt));
    else setSecsLeft(null);
  }, [expiresAt]);

  useEffect(() => {
    if (secsLeft === null || secsLeft <= 0) return undefined;
    const iv = setInterval(() => {
      setSecsLeft(prev => {
        if (prev === null) return null;
        const next = prev - 1;
        if (next <= 0) { clearInterval(iv); return 0; }
        return next;
      });
    }, 1000);
    return () => clearInterval(iv);
  // Re-register only when transitioning from null → non-null.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [secsLeft !== null]);

  if (secsLeft === null) {
    return <span style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#6b7280' }}>{label} · --:--</span>;
  }
  if (secsLeft <= 0) {
    return <span style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#d32f2f', fontWeight: 600 }}>{label} · Expired</span>;
  }
  const style: React.CSSProperties = secsLeft < 300
    ? { color: '#f57c00', fontWeight: 600 }
    : { color: '#555' };
  return (
    <span style={{ fontFamily: 'monospace', fontSize: '0.85rem', ...style }}
      title={`Session expires at ${expiresAt}`}>
      {label} · {_rcptFormatMmSs(secsLeft)}
    </span>
  );
};

// ---------------------------------------------------------------------------
// AgentSessionReceiptCard
// ---------------------------------------------------------------------------

/**
 * AgentSessionReceiptCardComponent
 *
 * Named with the "Component" suffix so the lazy import in plugin.ts resolves
 * to the raw function. The public name "AgentSessionReceiptCard" is the
 * createComponentExtension wrapper exported from plugin.ts → index.ts.
 */
export const AgentSessionReceiptCardComponent = () => {
  const { entity } = useEntity();
  const discoveryApi = useApi(discoveryApiRef);
  // fetchApiRef.fetch() attaches the Backstage user JWT as Authorization: Bearer
  // so the /jit-approver proxy (credentials: forward) can forward the user
  // identity to jit-approver. Raw browser fetch() does NOT attach this token
  // and would 401 against any proxy configured with credentials: require or
  // credentials: forward.
  const fetchApi = useApi(fetchApiRef);

  // The panel requires the session_id to query. In the current data model
  // the session_id is not stored in any Sandbox CR annotation or entity field.
  // TODO: once TODO-B2 is implemented (GET /requests?sandbox=<name>), look up
  // the session_id from that list endpoint. For now, read from a hypothetical
  // annotation that the agent could set on the Sandbox CR.
  const sessionId: string | null =
    entity.metadata.annotations?.['nvidia-ida/jit-session-id'] ?? null;

  const [status, setStatus] = useState<SessionStatus | null>(null);
  const [summary, setSummary] = useState<SessionSummary | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!sessionId) {
      setLoading(false);
      return;
    }

    let cancelled = false;

    const fetchData = async () => {
      try {
        const proxyBase = await discoveryApi.getBaseUrl('proxy');

        // 1. GET /requests/{id}/status — REAL endpoint.
        //    fetchApi.fetch() attaches the Backstage user JWT so the proxy
        //    (credentials: forward) forwards it upstream. A raw fetch() here
        //    would return 401 once the proxy is wired.
        const statusResp = await fetchApi.fetch(
          `${proxyBase}/jit-approver/requests/${sessionId}/status`,
        );
        if (!statusResp.ok && statusResp.status !== 404) {
          throw new Error(`status ${statusResp.status}`);
        }
        const statusData: SessionStatus | null = statusResp.ok ? await statusResp.json() : null;

        // 2. GET /requests/{id}/summary — TODO-C1: does not exist yet.
        //    Returns 404 until jit-approver exposes this endpoint.
        //    Also uses fetchApi.fetch() for consistency.
        let summaryData: SessionSummary | null = null;
        try {
          const summaryResp = await fetchApi.fetch(
            `${proxyBase}/jit-approver/requests/${sessionId}/summary`,
          );
          if (summaryResp.ok) {
            summaryData = await summaryResp.json();
          }
          // 404 is expected until TODO-C1 is implemented — silently ignore.
        } catch {
          // best-effort; summary is optional
        }

        if (!cancelled) {
          setStatus(statusData);
          setSummary(summaryData);
          setLoading(false);
        }
      } catch (e: unknown) {
        if (!cancelled) {
          setStatusError(e instanceof Error ? e.message : 'fetch failed');
          setLoading(false);
        }
      }
    };

    fetchData();
    return () => { cancelled = true; };
  }, [sessionId, discoveryApi, fetchApi]);

  if (loading) {
    return <InfoCard title="Session Receipt"><em>Loading…</em></InfoCard>;
  }

  if (!sessionId) {
    return (
      <InfoCard title="Session Receipt">
        <EmptyState
          title="No JIT session recorded"
          description="The Sandbox CR has no nvidia-ida/jit-session-id annotation. The receipt card requires TODO-B2 (GET /requests?sandbox=<name>) to look up the session without a hardcoded ID."
          missing="data"
        />
      </InfoCard>
    );
  }

  if (statusError) {
    return (
      <InfoCard title="Session Receipt">
        <EmptyState
          title="Could not load session"
          description={`${statusError} — check /jit-approver proxy entry in developer-hub-app-config.`}
          missing="data"
        />
      </InfoCard>
    );
  }

  return (
    <InfoCard
      title="Session Receipt"
      subheader={status ? <TtlCountdownChip expiresAt={status.expires_at} label="session" /> : undefined}
    >
      {/* Session state badge */}
      <section>
        <strong>State:</strong>{' '}
        <code>{status?.state ?? 'unknown'}</code>
        {status?.pr_url && (
          <>
            {' | '}
            <a href={status.pr_url} target="_blank" rel="noreferrer">Approval PR</a>
          </>
        )}
      </section>

      {/* Allowed actions from agent-posted summary (TODO-C1) */}
      <section style={{ marginTop: 12 }}>
        <strong>Actions taken</strong>
        {summary ? (
          summary.actions_taken.length > 0 ? (
            <ul>
              {summary.actions_taken.map((a, i) => (
                <li key={i} style={{ fontSize: '0.85rem' }}>{a}</li>
              ))}
            </ul>
          ) : <p style={{ color: '#6b7280', fontSize: '0.85rem' }}>None recorded</p>
        ) : (
          <p style={{ color: '#f59e0b', fontSize: '0.85rem' }}>
            Not available yet — requires TODO-C1:
            GET /requests/{sessionId}/summary on jit-approver.
          </p>
        )}
      </section>

      {/* Errors from agent-posted summary (TODO-C1) */}
      <section style={{ marginTop: 12 }}>
        <strong>Errors / denials (agent-reported)</strong>
        {summary ? (
          summary.errors_encountered.length > 0 ? (
            <ul>
              {summary.errors_encountered.map((e, i) => (
                <li key={i} style={{ fontSize: '0.85rem', color: '#ef4444' }}>{e}</li>
              ))}
            </ul>
          ) : <p style={{ color: '#6b7280', fontSize: '0.85rem' }}>None</p>
        ) : (
          <p style={{ color: '#f59e0b', fontSize: '0.85rem' }}>
            Not available yet — requires TODO-C1 (same endpoint as above).
          </p>
        )}
      </section>

      {/* ext-proc denials — honest placeholder */}
      <section style={{ marginTop: 12, borderTop: '1px solid #e5e7eb', paddingTop: 8 }}>
        <strong>ext-proc gate denials</strong>
        <p style={{ fontSize: '0.85rem', color: '#6b7280' }}>
          Requires TODO-C2: GET /requests/{'{session_id}'}/receipt on jit-approver
          (Loki-aggregated). Until then, view in the{' '}
          <a href="http://172.16.2.252:3000" target="_blank" rel="noreferrer">
            Grafana JIT Audit dashboard
          </a>{' '}
          (dashboard defined in
          platform/observability/grafana-dashboards/base/jit-audit-dashboard-cm.yaml).
        </p>
      </section>

      {/* Kube-audit section — honest TODO */}
      <section style={{ marginTop: 8 }}>
        <strong>Kube-audit attribution</strong>
        <p style={{ fontSize: '0.85rem', color: '#6b7280' }}>
          TODO-C3: kube-apiserver audit log access requires a privileged node-level
          proxy — not available via RHDH in Phase-3. Stub for Phase-4.
        </p>
      </section>
    </InfoCard>
  );
};
