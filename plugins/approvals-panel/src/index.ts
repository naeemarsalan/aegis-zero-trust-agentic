/**
 * Entry point for the nvidia-ida approvals-panel dynamic plugin.
 *
 * Scalprum module federation resolves this file as "PluginRoot"
 * (configured in package.json scalprum.exposedModules).
 *
 * JitApprovalsPanelCard calls useApi(discoveryApiRef). Exporting a bare React
 * component from index.ts would cause useApi() to throw at runtime because
 * the Backstage ApiHolder context would not be present. The component is
 * therefore wrapped in createComponentExtension (in plugin.ts), which provides
 * ApiHolder — the same pattern the keystone plan-consent plugin uses for its
 * page, and that the sibling receipt plugin uses for its card.
 */
export { approvalsPanelPlugin, JitApprovalsPanelCard } from './plugin';
