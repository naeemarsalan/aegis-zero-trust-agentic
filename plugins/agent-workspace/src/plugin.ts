/**
 * Plugin registration for agent-workspace.
 *
 * Wraps SandboxWorkspaceCard in createComponentExtension so that the
 * Backstage ApiHolder context is properly provided when Scalprum resolves
 * the importName "SandboxWorkspaceCard" from this package at a mountPoint.
 *
 * A bare React export referenced by importName works only when the component
 * does NOT call useApi() internally. SandboxWorkspaceCard does not call
 * useApi() today, but the consistent pattern (matching keystone plan-consent
 * and the two sibling plugins that DO call useApi) is to always provide the
 * ApiHolder context via createComponentExtension. This ensures the component
 * remains loadable if useApi() is added in a future iteration without a
 * packaging change.
 */

import { createPlugin, createComponentExtension } from '@backstage/core-plugin-api';

export const agentWorkspacePlugin = createPlugin({
  id: 'agent-workspace',
});

/**
 * SandboxWorkspaceCard
 *
 * Exported for RHDH mountPoint wiring:
 *   mountPoints:
 *     - mountPoint: entity.page.workspace/cards
 *       importName: SandboxWorkspaceCard
 */
export const SandboxWorkspaceCard = agentWorkspacePlugin.provide(
  createComponentExtension({
    name: 'SandboxWorkspaceCard',
    component: {
      lazy: () =>
        import('./components/SandboxWorkspaceCard').then(
          (m) => m.SandboxWorkspaceCardComponent,
        ),
    },
  }),
);
