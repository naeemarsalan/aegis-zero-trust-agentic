/**
 * usePlanData — resolves plan-consent page data from query params + catalog.
 *
 * DATA SOURCES (in priority order):
 *
 * 1. Query params (REAL, always available at page load):
 *    Delivered by the scaffolder output link from template.yaml:
 *      sandbox, scope, ttl, capabilities (csv), goal, owner
 *    These are query-string values — no fetch needed.
 *
 * 2. Backstage catalog API (REAL):
 *    GET /api/catalog/entities/by-name/resource/default/{name}
 *    Resolves each capability name to a CapabilityMeta (tier, jitRequired,
 *    toolsReadOnly, toolsPrivileged, description).
 *    Standard Backstage catalog REST — no custom proxy needed.
 *
 * 3. TODO-A1 — POST /api/proxy/mcp-launcher/plans (NOT YET IMPLEMENTED):
 *    The sandbox-launcher does not expose a /plans endpoint.
 *    When it does, replace the query-param parsing below with a single
 *    POST to /api/proxy/mcp-launcher/plans and use PlanResponse directly.
 *    See services/sandbox-launcher/src/sandbox_launcher/api.py for the
 *    add-location for the new endpoint.
 */

import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { fetchCapabilities } from '../api/catalogClient';
import { CapabilityMeta, ConsentQueryParams } from '../api/types';

export interface PlanData {
  sandboxName: string;
  scope: string;
  ttlMinutes: number;
  goal: string;
  owner: string;
  capabilityNames: string[];
  /** Resolved from catalog; null entries = entity not found or catalog error */
  capabilities: Map<string, CapabilityMeta | null>;
  loading: boolean;
  error: string | null;
}

function parseQueryParams(search: string): ConsentQueryParams {
  const p = new URLSearchParams(search);
  return {
    sandbox: p.get('sandbox') ?? '',
    scope: p.get('scope') ?? 'read-only',
    ttl: p.get('ttl') ?? '60',
    capabilities: p.get('capabilities') ?? '',
    goal: p.get('goal') ?? undefined,
    owner: p.get('owner') ?? undefined,
  };
}

/**
 * Hook that resolves plan data for the ConsentPage.
 *
 * @param discoveryApi - Backstage DiscoveryApi (from createApiRef resolution)
 * @param fetchApi     - Backstage FetchApi
 */
export function usePlanData(
  discoveryApi: { getBaseUrl: (id: string) => Promise<string> },
  fetchApi: { fetch: typeof fetch },
): PlanData {
  const location = useLocation();
  const params = parseQueryParams(location.search);

  const capabilityNames = params.capabilities
    ? params.capabilities.split(',').map((c) => c.trim()).filter(Boolean)
    : [];

  const [capabilities, setCapabilities] = useState<Map<string, CapabilityMeta | null>>(new Map());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (capabilityNames.length === 0) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    fetchCapabilities(discoveryApi, fetchApi, capabilityNames)
      .then((map) => {
        if (!cancelled) {
          setCapabilities(map);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          // Fail closed: surface error; do not silently show empty capabilities.
          const msg = err instanceof Error ? err.message : String(err);
          setError(`Failed to load capability details from catalog: ${msg}`);
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
    // Intentionally omit capabilityNames from deps to avoid re-running on
    // every render — parse once from location.search which is stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.search]);

  return {
    sandboxName: params.sandbox,
    scope: params.scope,
    ttlMinutes: parseInt(params.ttl, 10) || 60,
    goal: params.goal ?? '(no goal specified)',
    owner: params.owner ?? 'user:default/unknown',
    capabilityNames,
    capabilities,
    loading,
    error,
  };
}
