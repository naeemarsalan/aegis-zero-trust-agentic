/**
 * ConsentPage — the Plan & Consent keystone screen (Phase-3 Screen 1).
 *
 * Route:  /agent-consent  (dynamicRoute, registered via pluginConfig)
 * Import: AgentConsentPage
 *
 * ─── PURPOSE ──────────────────────────────────────────────────────────────
 *
 * Front-loaded consent: shown AFTER the scaffolder creates the sandbox but
 * BEFORE the user interacts with the agent. The user sees:
 *   - The exact sandbox that was created (name, scope, TTL)
 *   - The full capability manifest (what the agent CAN reach)
 *   - JIT badges on privileged capabilities (needs-approval)
 *   - A live advisory countdown chip (sandbox TTL from query param)
 *   - An explicit "I acknowledge" checkbox + Proceed button
 *   - A Deny/Abandon button (does NOT call a teardown API — see caveat)
 *
 * ─── DATA SOURCES ─────────────────────────────────────────────────────────
 *
 * 1. Query params (REAL, delivered by scaffolder output link):
 *    sandbox, scope, ttl, capabilities (csv), goal, owner
 *    Produced by the "Review agent plan and confirm" output.links entry
 *    added to platform/devhub/templates/run-agent/template.yaml.
 *
 * 2. Backstage catalog API (REAL):
 *    GET /api/catalog/entities/by-name/resource/default/{name}
 *    Resolves each capability name (e.g. "mcp-pfsense") to its full
 *    metadata including tier, jitRequired, toolsReadOnly, toolsPrivileged.
 *    All label/annotation keys are confirmed in platform/devhub/catalog/*.yaml.
 *
 * 3. TODO-A1 — POST /api/proxy/mcp-launcher/plans (NOT IMPLEMENTED):
 *    The sandbox-launcher has no /plans endpoint. When added, the page would
 *    call it to get a server-validated PlanResponse including estimated_tools
 *    and network_floor from the OpenShell baseline policy. See api/types.ts
 *    for the PlanResponse shape. Replace usePlanData() catalog calls with
 *    a single POST to /api/proxy/mcp-launcher/plans.
 *
 * ─── CAVEATS ──────────────────────────────────────────────────────────────
 *
 * - Deny button: calls window.history.back() only. There is no
 *   DELETE /launch/{name} or sandbox teardown endpoint. The sandbox auto-
 *   expires via TTL. Document this to users via InlineNote.
 *
 * - The TtlCountdownChip here is ADVISORY (pre-issuance mode). The real
 *   session expiry countdown is driven by SessionStatus.expires_at on
 *   Screen 3 (approvals panel) after a JIT credential is issued.
 *
 * - The sandbox may still be in PROVISIONING phase when this page loads.
 *   The consent page does NOT poll sandbox phase (no REST endpoint exists
 *   for phase polling — TODO-D3). Phase is visible on the Kubernetes tab
 *   of the entity page after the user clicks Proceed.
 */

import React, { useState } from 'react';
import {
  Page,
  Header,
  Content,
  InfoCard,
  Progress,
  ErrorPanel,
} from '@backstage/core-components';
import {
  useApi,
  discoveryApiRef,
  fetchApiRef,
} from '@backstage/core-plugin-api';
import { useNavigate } from 'react-router-dom';
import { TtlCountdownChip } from './TtlCountdownChip';
import { CapabilityRow } from './CapabilityRow';
import { usePlanData } from '../hooks/usePlanData';

// ---------------------------------------------------------------------------
// Styles (inline — no CSS module toolchain needed for a dynamic plugin)
// ---------------------------------------------------------------------------

const styles = {
  headerMeta: {
    display: 'flex' as const,
    gap: 16,
    flexWrap: 'wrap' as const,
    marginBottom: 8,
    alignItems: 'center' as const,
  },
  chip: (color: string, bg: string): React.CSSProperties => ({
    display: 'inline-block',
    padding: '3px 10px',
    borderRadius: 12,
    fontSize: '0.82em',
    fontWeight: 600,
    color,
    backgroundColor: bg,
  }),
  capTable: {
    width: '100%',
    borderCollapse: 'collapse' as const,
    fontSize: '0.9em',
  } as React.CSSProperties,
  capTableHead: {
    backgroundColor: '#f5f5f5',
    textAlign: 'left' as const,
    fontSize: '0.8em',
    color: '#555',
    padding: '6px 12px',
  } as React.CSSProperties,
  checkRow: {
    display: 'flex' as const,
    alignItems: 'center' as const,
    gap: 8,
    margin: '20px 0 8px',
    fontSize: '0.92em',
    cursor: 'pointer' as const,
  },
  proceedBtn: (disabled: boolean): React.CSSProperties => ({
    padding: '10px 28px',
    backgroundColor: disabled ? '#ccc' : '#1976d2',
    color: '#fff',
    border: 'none',
    borderRadius: 4,
    fontSize: '1em',
    fontWeight: 600,
    cursor: disabled ? 'not-allowed' : 'pointer',
    marginRight: 12,
  }),
  denyBtn: {
    padding: '10px 24px',
    backgroundColor: 'transparent',
    color: '#d32f2f',
    border: '1px solid #d32f2f',
    borderRadius: 4,
    fontSize: '1em',
    cursor: 'pointer',
  } as React.CSSProperties,
  noteBox: {
    marginTop: 16,
    padding: '10px 14px',
    backgroundColor: '#fffde7',
    border: '1px solid #f9a825',
    borderRadius: 4,
    fontSize: '0.83em',
    color: '#555',
  } as React.CSSProperties,
  infoRow: {
    display: 'flex' as const,
    gap: 8,
    alignItems: 'baseline' as const,
    marginBottom: 4,
  },
  label: {
    fontWeight: 600,
    minWidth: 80,
    color: '#444',
    fontSize: '0.85em',
  } as React.CSSProperties,
  value: {
    fontFamily: 'monospace',
    fontSize: '0.88em',
    color: '#222',
  } as React.CSSProperties,
};

// ---------------------------------------------------------------------------
// Scope chip colour
// ---------------------------------------------------------------------------

function scopeChipStyle(scope: string): React.CSSProperties {
  switch (scope) {
    case 'admin':
      return styles.chip('#b71c1c', '#ffebee');
    case 'read-write':
      return styles.chip('#e65100', '#fff3e0');
    default:
      return styles.chip('#1b5e20', '#e8f5e9');
  }
}

// ---------------------------------------------------------------------------
// Entity page URL — the "Proceed" navigation target
// ---------------------------------------------------------------------------

function sandboxEntityUrl(sandboxName: string): string {
  // Navigate to the catalog entity page for the sandbox Resource entity.
  // The entity is registered as resource:default/<sandbox_name>.
  // RHDH's /catalog/<namespace>/<kind>/<name> route resolves this.
  return `/catalog/default/resource/${encodeURIComponent(sandboxName)}`;
}

// ---------------------------------------------------------------------------
// ConsentPage
// ---------------------------------------------------------------------------

export const ConsentPage = (): React.ReactElement => {
  const discoveryApi = useApi(discoveryApiRef);
  const fetchApi = useApi(fetchApiRef);
  const navigate = useNavigate();

  const { sandboxName, scope, ttlMinutes, goal, owner, capabilityNames, capabilities, loading, error } =
    usePlanData(discoveryApi, fetchApi);

  const [acknowledged, setAcknowledged] = useState(false);

  const hasPrivileged = Array.from(capabilities.values()).some(
    (m) => m !== null && m.jitRequired,
  );

  const handleProceed = () => {
    if (!acknowledged) return;
    // TODO-E1 (BLOCKING): The target entity page at /catalog/default/resource/<name>
    // will return a 404 / empty state until the catalog:register step in
    // platform/devhub/templates/run-agent/template.yaml (lines 263-269) is
    // uncommented AND sandbox-launcher emits a catalogInfoUrl in its
    // LaunchResponse (see services/sandbox-launcher/src/sandbox_launcher/api.py).
    // Until that two-part fix lands, Proceed navigates to a non-existent entity.
    // See plugins/PHASE3.md "BLOCKING PREREQUISITE for Screens 2-4" for details.
    navigate(sandboxEntityUrl(sandboxName));
  };

  const handleDeny = () => {
    // There is no DELETE /launch/{name} endpoint.
    // The sandbox auto-expires via nvidia-ida/ttl-minutes label TTL.
    // We navigate away and let the sandbox expire on its own.
    // TODO: when a teardown endpoint is added to sandbox-launcher,
    // call DELETE /api/proxy/mcp-launcher/sandboxes/{sandboxName} here.
    window.history.back();
  };

  if (!sandboxName) {
    return (
      <Page themeId="tool">
        <Header title="Agent Plan & Consent" subtitle="nvidia-ida zero-trust platform" />
        <Content>
          <ErrorPanel
            title="Missing query parameters"
            error={new Error(
              'This page must be reached via the scaffolder output link. ' +
                'Required query params: sandbox, scope, ttl, capabilities.',
            )}
          />
        </Content>
      </Page>
    );
  }

  return (
    <Page themeId="tool">
      <Header
        title="Review agent plan and confirm"
        subtitle={
          <span style={styles.headerMeta}>
            <TtlCountdownChip
              ttlMinutes={ttlMinutes}
              label="current powers"
            />
            <span style={scopeChipStyle(scope)}>{scope}</span>
          </span>
        }
      />
      <Content>
        {/* ── Sandbox summary ── */}
        <InfoCard title="Sandbox" noPadding={false}>
          <div style={styles.infoRow}>
            <span style={styles.label}>Sandbox</span>
            <span style={styles.value}>{sandboxName}</span>
          </div>
          <div style={styles.infoRow}>
            <span style={styles.label}>Owner</span>
            <span style={styles.value}>{owner}</span>
          </div>
          <div style={styles.infoRow}>
            <span style={styles.label}>Scope</span>
            <span style={{ ...styles.value, ...scopeChipStyle(scope) }}>{scope}</span>
          </div>
          <div style={styles.infoRow}>
            <span style={styles.label}>TTL</span>
            <span style={styles.value}>{ttlMinutes} minutes (requested)</span>
          </div>
          {goal && (
            <div style={{ ...styles.infoRow, marginTop: 8 }}>
              <span style={styles.label}>Goal</span>
              <span style={{ ...styles.value, fontFamily: 'inherit', color: '#333' }}>{goal}</span>
            </div>
          )}
          <div style={styles.noteBox}>
            <strong>Phase note:</strong> The sandbox may still be in PROVISIONING phase. Phase
            polling is not available on this page (TODO-D3 — add GET /sandboxes/{'{name}'}/status
            to sandbox-launcher). The Kubernetes tab on the entity page shows live phase once
            the k8s plugin is wired (see platform/devhub/k8s-plugin.md).
          </div>
        </InfoCard>

        {/* ── Capability manifest ── */}
        <div style={{ marginTop: 16 }}>
        <InfoCard
          title="Capability manifest"
          subheader={
            hasPrivileged
              ? 'One or more capabilities require JIT approval before privileged tools can be called.'
              : 'All capabilities in this plan are read-only and auto-approved.'
          }
        >
          {/* TODO-A1: when POST /api/proxy/mcp-launcher/plans exists, replace
              the catalog-sourced capability rows with the PlanResponse.estimated_tools
              list and PlanResponse.network_floor summary block. */}
          {loading && <Progress />}
          {error && (
            <ErrorPanel
              title="Could not load capability details"
              error={new Error(error)}
            />
          )}
          {!loading && !error && (
            <table style={styles.capTable}>
              <thead>
                <tr>
                  <th style={styles.capTableHead}>Capability</th>
                  <th style={styles.capTableHead}>Approval</th>
                  <th style={styles.capTableHead}>Tools</th>
                </tr>
              </thead>
              <tbody>
                {capabilityNames.length === 0 ? (
                  <tr>
                    <td colSpan={3} style={{ padding: 12, color: '#999' }}>
                      No capabilities specified in the launch request.
                    </td>
                  </tr>
                ) : (
                  capabilityNames.map((name) => (
                    <CapabilityRow
                      key={name}
                      name={name}
                      meta={capabilities.get(name) ?? null}
                      jitDurationMinutes={ttlMinutes}
                    />
                  ))
                )}
              </tbody>
            </table>
          )}

          {/* ── Network floor note ── */}
          <div style={{ ...styles.noteBox, marginTop: 16 }}>
            <strong>Network floor:</strong> All agent traffic is deny-by-default per{' '}
            <code>platform/openshell/policies/baseline.yaml</code>. Privileged capabilities
            may request temporary egress widenings (policy_delta) which are reviewed in the
            JIT approval PR before being applied. Read-only capabilities operate within the
            existing floor — no widenings needed.
            {/* TODO-A1: render PlanResponse.policy_delta here when /plans endpoint exists */}
          </div>
        </InfoCard>
        </div>

        {/* ── Consent action ── */}
        <div style={{ marginTop: 16 }}>
        <InfoCard
          title="Approve scoped session"
          subheader="By proceeding you acknowledge that the agent will operate with the capabilities listed above."
        >
          <label style={styles.checkRow}>
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              style={{ width: 18, height: 18, cursor: 'pointer' }}
            />
            <span>
              I acknowledge that <strong>{sandboxName}</strong> will operate with{' '}
              <strong>{scope}</strong> scope for up to <strong>{ttlMinutes} minutes</strong>.
              {hasPrivileged && (
                <>
                  {' '}
                  Privileged tools will require JIT approval before execution — I will be
                  notified via Forgejo PR.
                </>
              )}
            </span>
          </label>

          <div style={{ marginTop: 8 }}>
            <button
              style={styles.proceedBtn(!acknowledged)}
              onClick={handleProceed}
              disabled={!acknowledged}
              aria-label="Proceed to agent workspace entity page"
            >
              Proceed to workspace
            </button>
            <button
              style={styles.denyBtn}
              onClick={handleDeny}
              aria-label="Abandon this session and navigate away"
            >
              Abandon
            </button>
          </div>

          <div style={styles.noteBox}>
            <strong>Abandon note:</strong> The Abandon button navigates away only. There is no
            sandbox teardown endpoint (TODO — add DELETE /launch/{'{'}<em>name</em>{'}'} to
            sandbox-launcher). The sandbox auto-expires after {ttlMinutes} minutes via the{' '}
            <code>nvidia-ida/ttl-minutes</code> TTL label on the OpenShell Sandbox CR.
          </div>
        </InfoCard>
        </div>
      </Content>
    </Page>
  );
};
