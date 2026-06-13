/**
 * Plugin registration for receipt.
 *
 * AgentSessionReceiptCard calls useApi(discoveryApiRef) internally.  A bare
 * React export referenced by importName from a mountPoint config will NOT
 * have the Backstage ApiHolder context in scope — useApi() will throw at
 * runtime with "No implementation found for apiRef".
 *
 * The fix is createComponentExtension, which wraps the component inside the
 * plugin's ApiHolder provider exactly as createRoutableExtension does for
 * pages. This matches the pattern used by the keystone plan-consent plugin
 * and by the sibling approvals-panel plugin.
 */

import { createPlugin, createComponentExtension } from '@backstage/core-plugin-api';

export const receiptPlugin = createPlugin({
  id: 'receipt',
});

/**
 * AgentSessionReceiptCard
 *
 * Exported for RHDH mountPoint wiring:
 *   mountPoints:
 *     - mountPoint: entity.page.overview/cards
 *       importName: AgentSessionReceiptCard
 */
export const AgentSessionReceiptCard = receiptPlugin.provide(
  createComponentExtension({
    name: 'AgentSessionReceiptCard',
    component: {
      lazy: () =>
        import('./components/AgentSessionReceiptCard').then(
          (m) => m.AgentSessionReceiptCardComponent,
        ),
    },
  }),
);
