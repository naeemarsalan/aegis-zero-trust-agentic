/**
 * Unit tests for SandboxWorkspaceCardComponent.
 * No network. No filesystem beyond t.TempDir equivalent.
 * Uses a minimal entity stub that satisfies useEntity().
 *
 * The component under test is the raw SandboxWorkspaceCardComponent (not the
 * createComponentExtension wrapper). Testing the wrapper would require a full
 * Backstage app context; testing the raw component is the correct unit-test
 * boundary.
 *
 * TtlCountdownChip NOTE: the chip now uses setInterval (ticking, not static).
 * Tests use jest.useFakeTimers() where timer-sensitive assertions are needed.
 */

import React from 'react';
import { render, screen, act } from '@testing-library/react';

// ---------------------------------------------------------------------------
// Mock @backstage/plugin-catalog-react so tests run without a full Backstage
// app context.
// ---------------------------------------------------------------------------
jest.mock('@backstage/plugin-catalog-react', () => ({
  useEntity: jest.fn(),
}));

jest.mock('@backstage/core-components', () => ({
  InfoCard: ({
    title,
    subheader,
    children,
  }: {
    title: string;
    subheader?: React.ReactNode;
    children: React.ReactNode;
  }) => (
    <div data-testid="info-card" data-title={title}>
      {subheader && <div data-testid="info-card-subheader">{subheader}</div>}
      {children}
    </div>
  ),
  Progress: () => <div data-testid="progress" />,
}));

import { SandboxWorkspaceCardComponent } from './SandboxWorkspaceCard';
import { useEntity } from '@backstage/plugin-catalog-react';

const mockUseEntity = useEntity as jest.Mock;

describe('SandboxWorkspaceCardComponent', () => {
  const baseEntity = {
    apiVersion: 'backstage.io/v1alpha1',
    kind: 'Resource',
    metadata: {
      name: 'agent-arsalan-a3f2',
      labels: {
        'nvidia-ida/ttl-minutes': '60',
        'nvidia-ida/scope': 'read-write',
      },
      annotations: {},
    },
    spec: { type: 'agent-sandbox' },
    relations: [],
  };

  it('happy path: renders phase and scope from entity labels', () => {
    mockUseEntity.mockReturnValue({ entity: baseEntity });

    render(<SandboxWorkspaceCardComponent />);

    expect(screen.getByText('PROVISIONING')).toBeInTheDocument();
    expect(screen.getByText('read-write')).toBeInTheDocument();
  });

  it('deny path: shows TODO placeholder when access_hint annotation is absent', () => {
    mockUseEntity.mockReturnValue({ entity: baseEntity });

    render(<SandboxWorkspaceCardComponent />);

    expect(
      screen.getByText(/access_hint not in CR annotation yet/i),
    ).toBeInTheDocument();
  });

  it('shows conversation_url TODO when null', () => {
    mockUseEntity.mockReturnValue({ entity: baseEntity });

    render(<SandboxWorkspaceCardComponent />);

    expect(
      screen.getByText(/not available yet/i),
    ).toBeInTheDocument();
  });

  it('renders access_hint when annotation is present', () => {
    const entityWithHint = {
      ...baseEntity,
      metadata: {
        ...baseEntity.metadata,
        annotations: {
          'nvidia-ida/access-hint': 'oc -n openshell exec -it agent-arsalan-a3f2 -c agent -- /bin/sh',
        },
      },
    };
    mockUseEntity.mockReturnValue({ entity: entityWithHint });

    render(<SandboxWorkspaceCardComponent />);

    expect(
      screen.getByText('oc -n openshell exec -it agent-arsalan-a3f2 -c agent -- /bin/sh'),
    ).toBeInTheDocument();
  });

  it('TtlCountdownChip is live (ticks) — advisory path with ttlMinutes seed', () => {
    // Confirms the chip uses setInterval and is NOT a static stub.
    // The chip initial value for 60m = 3600s → formatted as "60:00".
    // After 1 tick it becomes 3599s → "59:59".
    jest.useFakeTimers();
    mockUseEntity.mockReturnValue({ entity: baseEntity }); // ttl-minutes: 60

    render(<SandboxWorkspaceCardComponent />);

    // Initial render: chip shows 60:00
    expect(screen.getByText(/60:00/)).toBeInTheDocument();

    // Advance 1 second
    act(() => { jest.advanceTimersByTime(1000); });

    // Chip should now show 59:59
    expect(screen.getByText(/59:59/)).toBeInTheDocument();

    jest.useRealTimers();
  });
});
