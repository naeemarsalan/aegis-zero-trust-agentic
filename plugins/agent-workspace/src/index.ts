/**
 * Entry point for the nvidia-ida agent-workspace dynamic plugin.
 *
 * Scalprum module federation resolves this file as "PluginRoot"
 * (configured in package.json scalprum.exposedModules).
 *
 * SandboxWorkspaceCard is the createComponentExtension wrapper produced by
 * agentWorkspacePlugin.provide() in plugin.ts. This ensures the Backstage
 * ApiHolder context is available to the component when Scalprum resolves
 * importName: SandboxWorkspaceCard at the mountPoint.
 *
 * A bare React component export (the prior shape) is the wrong packaging
 * contract for RHDH mountPoint cards that need ApiHolder — the ApiHolder
 * context is provided by the plugin wrapper, not by Scalprum itself.
 */
export { agentWorkspacePlugin, SandboxWorkspaceCard } from './plugin';
