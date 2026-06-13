/**
 * JitApprovalsPanelCard — SKELETON
 *
 * mountPoint:  entity.page.approvals/cards
 * entityTab:   path=/approvals  title="Approvals"
 *
 * Condition:   isKind: resource  AND  isType: agent-sandbox
 *
 * ─── REAL DATA SOURCES ────────────────────────────────────────────────────
 *
 * 1. Session status (state, pr_url, expires_at, tool_scope)
 *    Endpoint:  GET /api/proxy/jit-approver/requests/{session_id}/status
 *    Response:  SessionStatus  { id, state, pr_url, expires_at,
 *                                session_jwt*, sa_token*, tool_scope* }
 *               (* present only when state == "issued")
 *    Source:    services/jit-approver/src/jit_approver/api.py:get_status()
 *    States:    pending | approved | issued | expired | denied
 *    Status:    REAL — endpoint exists and is confirmed in api.py line 155.
 *    Polling:   GET every 30 s from the panel (push not available; Forgejo
 *               webhook delivery unreliable on homelab per project memory).
 *
 * 2. RHDH proxy entry for jit-approver
 *    File:      platform/devhub/app-config-jit.yaml  (TODO — does not exist)
 *    Pattern:   Same hand-merge as app-config-launcher.yaml.
 *    Delta:
 *      proxy:
 *        endpoints:
 *          /jit-approver:
 *            target: http://jit-approver.mcp-gateway.svc:8080
 *            changeOrigin: true
 *            credentials: require
 *            allowedHeaders: [Content-Type]
 *            pathRewrite:
 *              '^/api/proxy/jit-approver/': '/'
 *
 * 3. Session list for a given sandbox
 *    MISSING — the jit-approver session_store is an in-memory dict keyed by
 *    UUID. There is no GET /requests list endpoint. The panel cannot enumerate
 *    sessions for a sandbox without knowing the UUIDs.
 *
 *    TODO-B2 (jit-approver api.py):
 *      Add GET /requests?sandbox=<name>
 *      Filter:  session_store.values() where session["request"].sandbox == param
 *      Return:  list[SessionStatus]  (subset of fields safe for the UI)
 *      This is a one-function addition to services/jit-approver/src/jit_approver/api.py.
 *
 * 4. JIT request detail (verbs, resources, namespace, justification, policy_delta)
 *    MISSING — GET /requests/{id}/status returns only SessionStatus.
 *    The stored EscalationRequest (verbs, resources, namespace, justification,
 *    policy_delta) is not surfaced by any existing endpoint.
 *
 *    TODO-B1 (jit-approver api.py):
 *      Add GET /requests/{session_id}/detail
 *      Return:  { state, expires_at } + EscalationRequest fields
 *               (agent_spiffe_id omitted for UI; verbs, resources, namespace,
 *               justification, policy_delta, sandbox included)
 *      Source:  session_store[session_id]["request"]
 *
 * 5. Forgejo PR approval
 *    Source:  pr_url field from GET /requests/{id}/status
 *    Pattern: External link to the Forgejo PR — approval IS the PR merge.
 *             No inline approve/deny button. Same approach as k8s-plugin.md §5a.
 *    Status:  REAL — pr_url is set immediately on POST /requests response.
 *
 * 6. TTL countdown
 *    Source:  expires_at (ISO-8601 from status endpoint; set only when issued)
 *             OR nvidia-ida/ttl-minutes entity label (pre-issuance seed)
 *    Computation: client-side setInterval; no server-side TTL-remaining field.
 *    Status:  REAL — expires_at is in SessionStatus model and api.py response.
 *
 * ─── CAVEATS ──────────────────────────────────────────────────────────────
 *
 * - session_store is in-memory only. On jit-approver pod eviction (SNO),
 *   all sessions are lost. GET /requests/{id}/status returns 404. Handle
 *   404 gracefully — treat as "session expired".
 *
 * - UpdateConfig gRPC outcome (openshell_widen_ok / openshell_widen_failed)
 *   has NO REST surface. It is in Loki only under {app="jit-approver"}.
 *   The panel cannot confirm whether the network floor was widened — show
 *   "state: approved" only; do not claim the widen succeeded.
 *
 * ─── BUILD STEPS ──────────────────────────────────────────────────────────
 *
 *   cd plugins/approvals-panel
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
 *             nvidia-ida.plugin-approvals-panel:
 *               entityTabs:
 *                 - path: /approvals
 *                   title: Approvals
 *                   mountPoint: entity.page.approvals
 *               mountPoints:
 *                 - mountPoint: entity.page.approvals/cards
 *                   importName: JitApprovalsPanelCard
 *                   config:
 *                     layout:
 *                       gridColumnEnd: span 12
 *                     if:
 *                       allOf:
 *                         - isKind: resource
 *                         - isType: agent-sandbox
 */

import React, { useEffect, useState } from 'react';
import { InfoCard, EmptyState } from '@backstage/core-components';
import { useEntity } from '@backstage/plugin-catalog-react';
import { useApi, discoveryApiRef, fetchApiRef } from '@backstage/core-plugin-api';

// ---------------------------------------------------------------------------
// Types matching services/jit-approver/src/jit_approver/models.py
// ---------------------------------------------------------------------------

type SessionState = 'pending' | 'approved' | 'issued' | 'expired' | 'denied';

interface SessionStatus {
  id: string;
  state: SessionState;
  pr_url: string | null;
  expires_at: string | null;
  tool_scope: string[] | null;
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

function _apprvFormatMmSs(totalSeconds: number): string {
  const clamped = Math.max(0, Math.floor(totalSeconds));
  const m = Math.floor(clamped / 60);
  const s = clamped % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

function _apprvSecsLeft(expiresAt: string): number {
  return (new Date(expiresAt).getTime() - Date.now()) / 1000;
}

const TtlCountdownChip = ({ expiresAt, label = 'expires' }: { expiresAt: string | null; label?: string }) => {
  const [secsLeft, setSecsLeft] = useState<number | null>(
    () => (expiresAt ? _apprvSecsLeft(expiresAt) : null),
  );

  useEffect(() => {
    if (expiresAt) setSecsLeft(_apprvSecsLeft(expiresAt));
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
    return <span style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{label} · pending issuance</span>;
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
      {label} · {_apprvFormatMmSs(secsLeft)}
    </span>
  );
};

// ---------------------------------------------------------------------------
// SessionRow
// ---------------------------------------------------------------------------

const STATE_COLOR: Record<SessionState, string> = {
  pending: '#f59e0b',
  approved: '#3b82f6',
  issued: '#22c55e',
  expired: '#9ca3af',
  denied: '#ef4444',
};

const SessionRow = ({ session }: { session: SessionStatus }) => (
  <div style={{ borderBottom: '1px solid #e5e7eb', padding: '8px 0' }}>
    <div>
      <span
        style={{
          display: 'inline-block',
          width: 10,
          height: 10,
          borderRadius: '50%',
          background: STATE_COLOR[session.state],
          marginRight: 6,
        }}
      />
      <strong>{session.state.toUpperCase()}</strong>
      {' — '}
      <code style={{ fontSize: '0.8rem' }}>{session.id.slice(0, 8)}…</code>
    </div>
    {session.tool_scope && (
      <div style={{ marginTop: 4, fontSize: '0.85rem' }}>
        Tools: {session.tool_scope.join(', ')}
      </div>
    )}
    <div style={{ marginTop: 4 }}>
      <TtlCountdownChip expiresAt={session.expires_at} label="expires" />
    </div>
    {session.pr_url && (
      <div style={{ marginTop: 4 }}>
        <a href={session.pr_url} target="_blank" rel="noreferrer">
          Review &amp; approve in Forgejo (merging the PR = approval)
        </a>
      </div>
    )}
  </div>
);

// ---------------------------------------------------------------------------
// JitApprovalsPanelCard
// ---------------------------------------------------------------------------

/**
 * JitApprovalsPanelCardComponent
 *
 * Named with the "Component" suffix so the lazy import in plugin.ts resolves
 * to the raw function. The public name "JitApprovalsPanelCard" is the
 * createComponentExtension wrapper exported from plugin.ts → index.ts.
 */
export const JitApprovalsPanelCardComponent = () => {
  const { entity } = useEntity();
  const discoveryApi = useApi(discoveryApiRef);
  // fetchApiRef.fetch() attaches the Backstage user JWT as Authorization: Bearer
  // so the /jit-approver proxy (credentials: forward) can forward the user
  // identity to jit-approver. A raw browser fetch() does NOT attach this token
  // and would 401 against the proxy once it is wired with credentials: forward.
  const fetchApi = useApi(fetchApiRef);

  const sandboxName = entity.metadata.name;

  // TODO-B2: replace stub with real fetch to GET /api/proxy/jit-approver/requests?sandbox=<name>
  // once that endpoint is added to services/jit-approver/src/jit_approver/api.py.
  const [sessions, setSessions] = useState<SessionStatus[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    const fetchSessions = async () => {
      try {
        // TODO-B2: replace with real endpoint once api.py adds:
        //   GET /requests?sandbox=<sandboxName>
        // When wiring, use fetchApi.fetch() (NOT the raw browser fetch) so the
        // Backstage user JWT is forwarded through the proxy:
        //   const proxyBase = await discoveryApi.getBaseUrl('proxy');
        //   const resp = await fetchApi.fetch(
        //     `${proxyBase}/jit-approver/requests?sandbox=${sandboxName}`,
        //   );
        //   if (resp.ok) setSessions(await resp.json());
        //
        // Stub: resolve the proxyBase so discoveryApi errors are surfaced, but
        // return empty sessions until TODO-B2 endpoint is implemented.
        await discoveryApi.getBaseUrl('proxy');
        if (!cancelled) {
          setSessions([]);
          setLoading(false);
        }
      } catch (e: unknown) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : 'fetch failed');
          setLoading(false);
        }
      }
    };

    fetchSessions();
    const timer = setInterval(fetchSessions, 30_000); // poll every 30 s
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [sandboxName, discoveryApi, fetchApi]);

  if (loading) {
    return <InfoCard title="JIT Approvals"><em>Loading…</em></InfoCard>;
  }

  if (error) {
    return (
      <InfoCard title="JIT Approvals">
        <EmptyState
          title="Could not load sessions"
          description={`${error} — check that the /jit-approver proxy entry exists in developer-hub-app-config.`}
          missing="data"
        />
      </InfoCard>
    );
  }

  return (
    <InfoCard
      title="JIT Approvals"
      subheader={`Sandbox: ${sandboxName}`}
    >
      {sessions.length === 0 ? (
        <EmptyState
          title="No active JIT sessions"
          description="Sessions appear here once the agent calls POST /requests on jit-approver. Requires TODO-B2 (GET /requests?sandbox= endpoint) to enumerate sessions for this sandbox."
          missing="data"
        />
      ) : (
        sessions.map(s => <SessionRow key={s.id} session={s} />)
      )}
      <p style={{ marginTop: 12, fontSize: '0.8rem', color: '#6b7280' }}>
        Approval = merging the Forgejo PR. Polls every 30 s.
        Requires TODO-B2: GET /requests?sandbox=&lt;name&gt; on jit-approver.
      </p>
    </InfoCard>
  );
};
