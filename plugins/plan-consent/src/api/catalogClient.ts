/**
 * catalogClient.ts — Backstage catalog REST calls for the plan-consent plugin.
 *
 * REAL DATA SOURCE:
 *   GET /api/catalog/entities/by-name/resource/default/{name}
 *   Standard Backstage catalog API — no custom backend required.
 *   Returns a full Backstage Entity object; we extract the fields we need.
 *
 * The capability entities (mcp-echo, mcp-pfsense) carry the labels and
 * annotations declared in platform/devhub/catalog/echo.yaml and pfsense.yaml.
 * These are confirmed real fields used throughout the agent gateway and
 * ext-proc delegation logic.
 */

import { CapabilityMeta } from './types';

// ---------------------------------------------------------------------------
// Backstage Entity shape (minimal — only the fields we consume)
// ---------------------------------------------------------------------------

interface BackstageEntityMetadata {
  name: string;
  title?: string;
  description?: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

interface BackstageEntity {
  metadata: BackstageEntityMetadata;
}

// ---------------------------------------------------------------------------
// Fetch a single capability entity from the catalog
// ---------------------------------------------------------------------------

/**
 * Fetches a capability Resource entity from the Backstage catalog API.
 *
 * @param discoveryApi - Backstage DiscoveryApi to resolve the catalog base URL
 * @param fetchApi - Backstage FetchApi (handles auth headers automatically)
 * @param entityName - Catalog entity name, e.g. "mcp-pfsense"
 */
export async function fetchCapabilityEntity(
  discoveryApi: { getBaseUrl: (id: string) => Promise<string> },
  fetchApi: { fetch: typeof fetch },
  entityName: string,
): Promise<CapabilityMeta | null> {
  const baseUrl = await discoveryApi.getBaseUrl('catalog');
  const url = `${baseUrl}/entities/by-name/resource/default/${encodeURIComponent(entityName)}`;

  let resp: Response;
  try {
    resp = await fetchApi.fetch(url);
  } catch (err) {
    // Network failure — fail closed: treat capability as unknown/unavailable.
    console.error(`[plan-consent] catalog fetch failed for ${entityName}:`, err);
    return null;
  }

  if (!resp.ok) {
    // 404 means the capability is not registered in the catalog — surface this
    // in the UI rather than silently hiding the row.
    console.warn(`[plan-consent] catalog returned ${resp.status} for entity ${entityName}`);
    return null;
  }

  const entity = (await resp.json()) as BackstageEntity;
  const { metadata } = entity;
  const labels = metadata.labels ?? {};
  const annotations = metadata.annotations ?? {};

  const tier = labels['nvidia-ida/capability-tier'] === 'privileged' ? 'privileged' : 'read-only';
  const jitRequired = labels['nvidia-ida/jit-required'] === 'true';

  return {
    name: metadata.name,
    title: metadata.title ?? metadata.name,
    description: metadata.description ?? '',
    tier,
    jitRequired,
    mcpEndpoint: annotations['nvidia-ida/mcp-endpoint'] ?? '',
    toolsReadOnly: annotations['nvidia-ida/tools-read-only'] ?? 'none',
    toolsPrivileged: annotations['nvidia-ida/tools-privileged'] ?? 'none',
  };
}

/**
 * Fetches all capability entities for a list of names.
 * Returns a map of name -> CapabilityMeta | null (null = not found or error).
 */
export async function fetchCapabilities(
  discoveryApi: { getBaseUrl: (id: string) => Promise<string> },
  fetchApi: { fetch: typeof fetch },
  names: string[],
): Promise<Map<string, CapabilityMeta | null>> {
  const results = await Promise.all(
    names.map(async (name) => {
      const meta = await fetchCapabilityEntity(discoveryApi, fetchApi, name);
      return [name, meta] as [string, CapabilityMeta | null];
    }),
  );
  return new Map(results);
}
