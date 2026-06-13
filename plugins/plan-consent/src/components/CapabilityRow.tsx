/**
 * CapabilityRow — single row in the capability manifest table.
 *
 * Shows:
 *   - Capability name and title (from catalog entity)
 *   - Tier badge: "read-only · auto" or "privileged · needs-approval"
 *   - JIT badge with requested duration when jitRequired === true
 *   - Tool summary (read-only tools / privileged tools from catalog annotations)
 *
 * DATA SOURCES (all REAL — confirmed in platform/devhub/catalog/pfsense.yaml
 * and echo.yaml):
 *   metadata.title                         — human title
 *   metadata.description                   — description
 *   labels['nvidia-ida/capability-tier']   — "read-only" | "privileged"
 *   labels['nvidia-ida/jit-required']      — "true" | "false"
 *   annotations['nvidia-ida/tools-read-only']   — tool names string
 *   annotations['nvidia-ida/tools-privileged']  — tool names string
 */

import React from 'react';
import { CapabilityMeta } from '../api/types';

interface CapabilityRowProps {
  /** Catalog entity name, e.g. "mcp-pfsense" */
  name: string;
  /** Resolved catalog metadata; null = entity not found */
  meta: CapabilityMeta | null;
  /** Requested JIT session duration in minutes (from TTL param) */
  jitDurationMinutes: number;
}

const tierStyles: Record<'read-only' | 'privileged', React.CSSProperties> = {
  'read-only': {
    backgroundColor: '#e8f5e9',
    color: '#2e7d32',
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: '0.8em',
    fontWeight: 600,
  },
  privileged: {
    backgroundColor: '#fff3e0',
    color: '#e65100',
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: '0.8em',
    fontWeight: 600,
  },
};

const jitBadgeStyle: React.CSSProperties = {
  display: 'inline-block',
  backgroundColor: '#fce4ec',
  color: '#c62828',
  padding: '2px 8px',
  borderRadius: 4,
  fontSize: '0.78em',
  fontWeight: 600,
  marginLeft: 8,
  border: '1px solid #ef9a9a',
};

export const CapabilityRow = ({
  name,
  meta,
  jitDurationMinutes,
}: CapabilityRowProps): React.ReactElement => {
  if (!meta) {
    return (
      <tr>
        <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>
          {name}
        </td>
        <td colSpan={3} style={{ padding: '8px 12px', color: '#999' }}>
          Capability not found in catalog — verify entity is registered in RHDH
        </td>
      </tr>
    );
  }

  const tierLabel =
    meta.tier === 'privileged' ? 'privileged · needs-approval' : 'read-only · auto';

  return (
    <tr style={{ borderBottom: '1px solid #f0f0f0' }}>
      <td style={{ padding: '10px 12px', verticalAlign: 'top' }}>
        <strong style={{ display: 'block', fontSize: '0.95em' }}>{meta.title}</strong>
        <span style={{ fontFamily: 'monospace', fontSize: '0.78em', color: '#666' }}>
          {meta.name}
        </span>
        <div style={{ fontSize: '0.8em', color: '#777', marginTop: 2 }}>
          {meta.description}
        </div>
      </td>

      <td style={{ padding: '10px 12px', verticalAlign: 'top', whiteSpace: 'nowrap' }}>
        <span style={tierStyles[meta.tier]}>{tierLabel}</span>
        {meta.jitRequired && (
          <span style={jitBadgeStyle} title={`Privileged tools in this capability require JIT approval (max ${jitDurationMinutes}m session)`}>
            JIT · {jitDurationMinutes}m
          </span>
        )}
      </td>

      <td style={{ padding: '10px 12px', verticalAlign: 'top', fontSize: '0.82em', color: '#444' }}>
        <div>
          <span style={{ color: '#2e7d32', fontWeight: 600 }}>Read-only: </span>
          {meta.toolsReadOnly}
        </div>
        {meta.tier === 'privileged' && (
          <div style={{ marginTop: 4 }}>
            <span style={{ color: '#e65100', fontWeight: 600 }}>Privileged: </span>
            {meta.toolsPrivileged}
          </div>
        )}
      </td>
    </tr>
  );
};
