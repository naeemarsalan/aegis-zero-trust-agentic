/**
 * SandboxWorkspaceCard — SKELETON
 *
 * mountPoint:  entity.page.workspace/cards
 * entityTab:   path=/workspace  title="Workspace"
 *
 * Condition:   isKind: resource  AND  isType: agent-sandbox
 *
 * ─── REAL DATA SOURCES ────────────────────────────────────────────────────
 *
 * 1. Sandbox phase
 *    Source:  Kubernetes API via @backstage/plugin-kubernetes context
 *             (useKubernetesObjects() hook).
 *    CR:      agents.x-k8s.io/v1alpha1 Sandbox in namespace "openshell"
 *    Field:   status.phase  mapped via phase_name():
 *               PROVISIONING | READY | ERROR | DELETING | UNKNOWN
 *    Status:  REAL — available once the k8s plugin custom resource is wired
 *             per platform/devhub/k8s-plugin.md step 1.
 *
 * 2. TTL / scope labels (for TtlCountdownChip seed)
 *    Source:  Same Kubernetes object from useKubernetesObjects().
 *    Labels:  nvidia-ida/ttl-minutes  (string, e.g. "60")
 *             nvidia-ida/scope        (e.g. "read-write")
 *    Status:  REAL — launcher stamps both at CreateSandbox time
 *             (services/sandbox-launcher/src/sandbox_launcher/api.py lines ~232).
 *
 * 3. access_hint
 *    Source:  MISSING — launcher returns it in LaunchResponse.access_hint
 *             but does NOT write it into any Sandbox CR annotation today.
 *    TODO-D3: services/sandbox-launcher/src/sandbox_launcher/openshell.py
 *             must patch the Sandbox CR with annotation
 *             "nvidia-ida/access-hint" after CreateSandbox.
 *             Without this, the card cannot surface the oc-exec command
 *             from the entity page (only from the scaffolder output screen).
 *
 * 4. conversation_url
 *    Source:  MISSING — LaunchResponse.conversation_url is always null at
 *             creation time. ExposeService gRPC exists in the proto stub
 *             (services/sandbox-launcher/src/sandbox_launcher/osh/
 *             openshell_pb2_grpc.py) but is never called.
 *    TODO-D1: Add POST /sandboxes/{sandbox_name}/expose to sandbox-launcher.
 *             Polls GetSandbox until READY, then calls ExposeService gRPC,
 *             returns {conversation_url, phase}. Frontend polls this endpoint
 *             after initial launch; card shows URL once non-null.
 *    Fallback: Display access_hint as a copyable oc-exec command (zero new
 *              backend code required once TODO-D3 is done).
 *
 * 5. JIT session state badge
 *    Source:  GET /api/proxy/jit-approver/requests/{session_id}/status
 *             → SessionStatus.state
 *    Status:  REAL endpoint on jit-approver. Requires RHDH proxy entry
 *             /jit-approver (see platform/devhub/app-config-jit.yaml TODO).
 *    Gap:     The workspace card cannot enumerate session IDs without
 *             TODO-B2 (GET /requests?sandbox=<name> list endpoint).
 *
 * ─── BUILD STEPS ──────────────────────────────────────────────────────────
 *
 *   cd plugins/agent-workspace
 *   yarn install
 *   npx @red-hat-developer-hub/cli@1.9.0 plugin export \
 *     --no-generate-module-federation-assets --clean
 *   cd dist-dynamic
 *   npm pack
 *   HASH=$(npm pack --json | jq -r '.[0].integrity')
 *   # Upload the .tgz to https://git.arsalan.io as a Gitea release attachment.
 *   # Add the ConfigMap delta below to developer-hub-dynamic-plugins.
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
 *             nvidia-ida.plugin-agent-workspace:
 *               entityTabs:
 *                 - path: /workspace
 *                   title: Workspace
 *                   mountPoint: entity.page.workspace
 *               mountPoints:
 *                 - mountPoint: entity.page.workspace/cards
 *                   importName: SandboxWorkspaceCard
 *                   config:
 *                     layout:
 *                       gridColumnEnd: span 12
 *                     if:
 *                       allOf:
 *                         - isKind: resource
 *                         - isType: agent-sandbox
 *
 * ─── PROXY DELTA (developer-hub-app-config) ───────────────────────────────
 *
 *   See platform/devhub/app-config-jit.yaml (to be created — same hand-merge
 *   pattern as app-config-launcher.yaml) for the /jit-approver proxy entry
 *   pointing at http://jit-approver.mcp-gateway.svc:8080.
 */

import React, { useEffect, useState } from 'react';
import {
  InfoCard,
  Progress,
} from '@backstage/core-components';
import { useEntity } from '@backstage/plugin-catalog-react';

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
// The countdown DOES tick (setInterval, 1 s); when expiresAt is null it falls
// back to an advisory countdown seeded from ttlMinutes (same behaviour as the
// real component's ttlMinutes-only path).
// ---------------------------------------------------------------------------

interface TtlCountdownChipProps {
  /** ISO-8601 from SessionStatus.expires_at; null when pre-issuance */
  expiresAt?: string | null;
  /** Fallback seed: nvidia-ida/ttl-minutes label value (string) */
  ttlMinutes?: number;
  label?: string;
}

function _wsFormatMmSs(totalSeconds: number): string {
  const clamped = Math.max(0, Math.floor(totalSeconds));
  const m = Math.floor(clamped / 60);
  const s = clamped % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

function _wsSecsLeft(expiresAt: string): number {
  return (new Date(expiresAt).getTime() - Date.now()) / 1000;
}

const TtlCountdownChip = ({ expiresAt, ttlMinutes, label = 'sandbox TTL' }: TtlCountdownChipProps) => {
  const [secsLeft, setSecsLeft] = useState<number | null>(() => {
    if (expiresAt) return _wsSecsLeft(expiresAt);
    if (ttlMinutes != null) return ttlMinutes * 60;
    return null;
  });

  useEffect(() => {
    if (expiresAt) setSecsLeft(_wsSecsLeft(expiresAt));
    else if (ttlMinutes != null) setSecsLeft(ttlMinutes * 60);
    else setSecsLeft(null);
  }, [expiresAt, ttlMinutes]);

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
    return <span style={{ fontFamily: 'monospace' }}>{label} · --:--</span>;
  }
  if (secsLeft <= 0) {
    return <span style={{ fontFamily: 'monospace', color: '#d32f2f', fontWeight: 600 }}>{label} · Expired</span>;
  }
  const isAdvisory = !expiresAt && ttlMinutes != null;
  const style: React.CSSProperties = secsLeft < 300
    ? { color: '#f57c00', fontWeight: 600 }
    : { color: '#555' };
  return (
    <span style={{ fontFamily: 'monospace', ...style }}
      title={isAdvisory
        ? `Advisory countdown — seeded from requested TTL (${ttlMinutes}m). Actual expiry starts when session is issued.`
        : `Session expires at ${expiresAt}`}>
      {label} · {_wsFormatMmSs(secsLeft)}
      {isAdvisory && <span style={{ fontSize: '0.75em', marginLeft: 4, opacity: 0.7 }}>(requested)</span>}
    </span>
  );
};

// ---------------------------------------------------------------------------
// SandboxWorkspaceCardComponent
//
// Named with the "Component" suffix so the default export consumed by
// createComponentExtension (in plugin.ts) can be lazy-loaded cleanly.
// The public API name "SandboxWorkspaceCard" is the plugin.provide() wrapper
// exported from plugin.ts and re-exported from index.ts.
// ---------------------------------------------------------------------------

export const SandboxWorkspaceCardComponent = () => {
  const { entity } = useEntity();

  // useEntity() throws if called outside a catalog entity context, so entity
  // is always defined here. The guard was removed — it was dead code positioned
  // after reads that would have already thrown on an undefined entity.

  // TODO: replace stub with useKubernetesObjects() from @backstage/plugin-kubernetes
  // to read the live Sandbox CR phase, labels, and annotations.
  const phase: string = (entity.metadata.annotations?.['nvidia-ida/phase'] ?? 'PROVISIONING');
  const ttlMinutes = parseInt(entity.metadata.labels?.['nvidia-ida/ttl-minutes'] ?? '60', 10);
  const scope = entity.metadata.labels?.['nvidia-ida/scope'] ?? 'read-only';

  // TODO-D3: read from annotation nvidia-ida/access-hint once launcher patches it.
  const accessHint: string | null = entity.metadata.annotations?.['nvidia-ida/access-hint'] ?? null;

  // TODO-D1: poll POST /sandboxes/{name}/expose for conversation_url once non-null.
  const conversationUrl: string | null = null;

  return (
    <InfoCard title="Agent Workspace" subheader={<TtlCountdownChip ttlMinutes={ttlMinutes} label="sandbox TTL" />}>
      <dl>
        <dt>Phase</dt>
        <dd>{phase}</dd>
        <dt>Scope</dt>
        <dd>{scope}</dd>
        <dt>Conversation URL</dt>
        <dd>
          {conversationUrl
            ? <a href={conversationUrl} target="_blank" rel="noreferrer">{conversationUrl}</a>
            : <em>Not available yet — sandbox still provisioning or ExposeService not called (TODO-D1)</em>
          }
        </dd>
        <dt>Shell access</dt>
        <dd>
          {accessHint
            ? <code>{accessHint}</code>
            : <em>access_hint not in CR annotation yet (TODO-D3 — patch sandbox-launcher/openshell.py)</em>
          }
        </dd>
      </dl>

      {/* TODO-D2: embed interactive terminal via ExecSandboxInteractive gRPC
          bridged through a WebSocket proxy. Out of scope for Phase-3 skeleton.
          The access_hint oc-exec command above is the PoC fallback. */}
    </InfoCard>
  );
};

// ---------------------------------------------------------------------------
// Keep a named Progress export so the test mock for Progress still resolves
// if any future code path needs a loading state. The current card has no
// loading state because entity is synchronously available from useEntity().
// ---------------------------------------------------------------------------
export { Progress };
