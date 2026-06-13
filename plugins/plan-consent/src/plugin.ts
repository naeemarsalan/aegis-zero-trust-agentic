/**
 * Plugin registration for plan-consent.
 *
 * This file is the Backstage plugin object. It registers the plugin ID
 * and the single routable extension (ConsentPage at /agent-consent).
 */

import { createPlugin, createRouteRef, createRoutableExtension } from '@backstage/core-plugin-api';

export const rootRouteRef = createRouteRef({ id: 'plan-consent' });

export const planConsentPlugin = createPlugin({
  id: 'plan-consent',
  routes: {
    root: rootRouteRef,
  },
});

/**
 * AgentConsentPage — the dynamicRoute component exported for RHDH wiring.
 *
 * Registered in pluginConfig.dynamicPlugins.frontend.nvidia-ida.plugin-plan-consent:
 *   dynamicRoutes:
 *     - path: /agent-consent
 *       importName: AgentConsentPage
 */
export const AgentConsentPage = planConsentPlugin.provide(
  createRoutableExtension({
    name: 'AgentConsentPage',
    component: () =>
      import('./components/ConsentPage').then((m) => m.ConsentPage),
    mountPoint: rootRouteRef,
  }),
);
