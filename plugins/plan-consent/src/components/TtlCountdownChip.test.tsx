/**
 * TtlCountdownChip tests.
 *
 * Uses fake timers to verify countdown behaviour without real-time waits.
 * No network access — pure component test.
 */

import React from 'react';
import { render, screen, act } from '@testing-library/react';
import { TtlCountdownChip } from './TtlCountdownChip';

describe('TtlCountdownChip', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('renders advisory countdown from ttlMinutes when expiresAt is absent', () => {
    render(<TtlCountdownChip ttlMinutes={2} label="current powers" />);
    // 2 minutes = 120 seconds → 2:00
    expect(screen.getByText(/current powers · 2:00/)).toBeInTheDocument();
    expect(screen.getByText(/\(requested\)/)).toBeInTheDocument();
  });

  it('counts down by 1 second per tick', () => {
    render(<TtlCountdownChip ttlMinutes={1} label="session expires" />);
    expect(screen.getByText(/session expires · 1:00/)).toBeInTheDocument();

    act(() => { jest.advanceTimersByTime(1000); });
    expect(screen.getByText(/session expires · 0:59/)).toBeInTheDocument();

    act(() => { jest.advanceTimersByTime(5000); });
    expect(screen.getByText(/session expires · 0:54/)).toBeInTheDocument();
  });

  it('shows "Expired" when time reaches zero', () => {
    render(<TtlCountdownChip ttlMinutes={0} label="current powers" />);
    // 0 minutes → already expired
    expect(screen.getByText(/Expired/)).toBeInTheDocument();
  });

  it('renders authoritative countdown from expiresAt (post-issuance mode)', () => {
    // Set expiresAt to 5 minutes in the future
    const future = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    render(<TtlCountdownChip expiresAt={future} label="session expires" />);
    // Should show approximately 5:00 — allow ±5 seconds for render timing
    expect(screen.getByText(/session expires · 4:/)).toBeInTheDocument();
    // No "(requested)" suffix in authoritative mode
    expect(screen.queryByText(/\(requested\)/)).not.toBeInTheDocument();
  });

  it('renders null state when neither expiresAt nor ttlMinutes is provided', () => {
    render(<TtlCountdownChip label="current powers" />);
    expect(screen.getByText(/current powers · --:--/)).toBeInTheDocument();
  });
});
