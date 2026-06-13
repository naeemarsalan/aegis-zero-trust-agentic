/**
 * TtlCountdownChip — shared "current powers · MM:SS left" chip.
 *
 * Used across all four Phase-3 screens:
 *   Screen 1 (plan-consent)  — seeded from TTL query param (advisory)
 *   Screen 2 (workspace)     — seeded from nvidia-ida/ttl-minutes CR label
 *   Screen 3 (approvals)     — driven by SessionStatus.expires_at (ISO-8601)
 *   Screen 4 (receipt)       — shows "Expired" when session is done
 *
 * DATA SOURCES:
 *   expiresAt  — ISO-8601 string from SessionStatus.expires_at (REAL when issued)
 *                GET /api/proxy/jit-approver/requests/{id}/status
 *   ttlMinutes — Number from nvidia-ida/ttl-minutes CR label OR query param "ttl"
 *                Both are REAL: launcher stamps the label; scaffolder passes the param.
 *
 * This component is EXPORTED from the plan-consent plugin so that the other
 * three plugin packages can import it once the workspace is published.
 * Until then, each plugin that needs it duplicates the import; the
 * SandboxWorkspaceCard.tsx already has an inline stub (to be replaced).
 */

import React, { useEffect, useState } from 'react';

export interface TtlCountdownChipProps {
  /**
   * ISO-8601 from SessionStatus.expires_at.
   * When provided, countdown is authoritative (server-side expiry).
   * Only present when state === 'issued'.
   */
  expiresAt?: string | null;
  /**
   * Fallback seed in minutes.
   * Used when expiresAt is null (pre-issuance): advisory countdown from page load.
   * Sources: "ttl" query param (Screen 1) or nvidia-ida/ttl-minutes CR label (Screen 2).
   */
  ttlMinutes?: number;
  /** Display label, e.g. "session expires" or "sandbox TTL" */
  label?: string;
}

function formatMmSs(totalSeconds: number): string {
  const clamped = Math.max(0, Math.floor(totalSeconds));
  const m = Math.floor(clamped / 60);
  const s = clamped % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

function secondsRemaining(expiresAt: string): number {
  const expiry = new Date(expiresAt).getTime();
  return (expiry - Date.now()) / 1000;
}

/**
 * Returns the chip color variant based on time remaining.
 *   < 0s  → expired (red-ish text)
 *   < 5m  → warning (amber)
 *   >= 5m → default (muted)
 */
function chipStyle(secs: number): React.CSSProperties {
  if (secs <= 0) {
    return { color: '#d32f2f', fontWeight: 600 };
  }
  if (secs < 300) {
    return { color: '#f57c00', fontWeight: 600 };
  }
  return { color: '#555', fontWeight: 400 };
}

export const TtlCountdownChip = ({
  expiresAt,
  ttlMinutes,
  label = 'current powers',
}: TtlCountdownChipProps): React.ReactElement => {
  const [secsLeft, setSecsLeft] = useState<number | null>(() => {
    if (expiresAt) {
      return secondsRemaining(expiresAt);
    }
    if (ttlMinutes != null) {
      return ttlMinutes * 60;
    }
    return null;
  });

  useEffect(() => {
    // Re-derive initial state when props change (e.g. expiresAt arrives
    // after an async status poll).
    if (expiresAt) {
      setSecsLeft(secondsRemaining(expiresAt));
    } else if (ttlMinutes != null) {
      setSecsLeft(ttlMinutes * 60);
    }
  }, [expiresAt, ttlMinutes]);

  useEffect(() => {
    if (secsLeft === null) return undefined;

    const interval = setInterval(() => {
      setSecsLeft((prev) => {
        if (prev === null) return null;
        const next = prev - 1;
        if (next <= 0) {
          clearInterval(interval);
          return 0;
        }
        return next;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [secsLeft !== null]);  // Only re-register when we go from null → non-null

  if (secsLeft === null) {
    return (
      <span style={{ fontFamily: 'monospace', color: '#999' }}>
        {label} · --:--
      </span>
    );
  }

  if (secsLeft <= 0) {
    return (
      <span style={{ fontFamily: 'monospace', ...chipStyle(0) }}>
        {label} · Expired
      </span>
    );
  }

  const isAdvisory = !expiresAt && ttlMinutes != null;

  return (
    <span
      style={{ fontFamily: 'monospace', ...chipStyle(secsLeft) }}
      title={
        isAdvisory
          ? `Advisory countdown — seeded from requested TTL (${ttlMinutes}m). ` +
            `Actual sandbox expiry starts when the session is issued.`
          : `Session expires at ${expiresAt}`
      }
    >
      {label} · {formatMmSs(secsLeft)}
      {isAdvisory && (
        <span style={{ fontSize: '0.75em', marginLeft: 4, opacity: 0.7 }}>
          (requested)
        </span>
      )}
    </span>
  );
};
