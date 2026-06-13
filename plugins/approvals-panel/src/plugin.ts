/**
 * Plugin registration for approvals-panel.
 *
 * JitApprovalsPanelCard calls useApi(discoveryApiRef) internally.  A bare
 * React export referenced by importName from a mountPoint config will NOT
 * have the Backstage ApiHolder context in scope — useApi() will throw at
 * runtime with "No implementation found for apiRef".
 *
 * The fix is createComponentExtension, which wraps the component inside the
 * plugin's ApiHolder provider exactly as createRoutableExtension does for
 * pages. This matches the pattern used by the keystone plan-consent plugin
 * and by the sibling receipt plugin.
 */

import { createPlugin, createComponentExtension } from '@backstage/core-plugin-api';

export const approvalsPanelPlugin = createPlugin({
  id: 'approvals-panel',
});

/**
 * JitApprovalsPanelCard
 *
 * Exported for RHDH mountPoint wiring:
 *   mountPoints:
 *     - mountPoint: entity.page.approvals/cards
 *       importName: JitApprovalsPanelCard
 */
export const JitApprovalsPanelCard = approvalsPanelPlugin.provide(
  createComponentExtension({
    name: 'JitApprovalsPanelCard',
    component: {
      lazy: () =>
        import('./components/JitApprovalsPanelCard').then(
          (m) => m.JitApprovalsPanelCardComponent,
        ),
    },
  }),
);
