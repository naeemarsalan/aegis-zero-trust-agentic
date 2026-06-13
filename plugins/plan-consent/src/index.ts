/**
 * Entry point for the nvidia-ida plan-consent dynamic plugin.
 *
 * Scalprum module federation resolves this file as "PluginRoot"
 * (configured in package.json scalprum.exposedModules).
 *
 * Exports:
 *   AgentConsentPage  — dynamicRoute component at /agent-consent
 *   TtlCountdownChip  — shared countdown chip (consumed by all 4 Phase-3 screens)
 *   planConsentPlugin — plugin registration object (Backstage convention)
 *
 * The other Phase-3 plugins (agent-workspace, approvals-panel, receipt) should
 * import TtlCountdownChip from this package once the workspace is published:
 *   import { TtlCountdownChip } from '@nvidia-ida/plugin-plan-consent';
 * Until then, each plugin carries an inline stub (see SandboxWorkspaceCard.tsx).
 */

export { planConsentPlugin, AgentConsentPage } from './plugin';
export { TtlCountdownChip } from './components/TtlCountdownChip';
export type { TtlCountdownChipProps } from './components/TtlCountdownChip';
