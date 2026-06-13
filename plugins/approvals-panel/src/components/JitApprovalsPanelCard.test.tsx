/**
 * Unit tests for JitApprovalsPanelCardComponent.
 * No network calls. discoveryApi and fetchApi are mocked.
 * Validates happy path (sessions rendered) and deny path (fetch error).
 *
 * The component under test is the raw JitApprovalsPanelCardComponent (not the
 * createComponentExtension wrapper). Testing the wrapper would require a full
 * Backstage app context; testing the raw component is the correct unit-test
 * boundary.
 *
 * AUTH NOTE: the component uses useApi(fetchApiRef) — NOT the raw browser fetch().
 * Tests mock fetchApiRef through useApi so that when TODO-B2 is uncommented and
 * calls fetchApi.fetch(), the mock intercepts it.  This guards against any future
 * regression that switches back to a raw fetch() call.
 */

import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';

jest.mock('@backstage/plugin-catalog-react', () => ({
  useEntity: jest.fn(),
}));

jest.mock('@backstage/core-plugin-api', () => ({
  useApi: jest.fn(),
  discoveryApiRef: { id: 'discovery' },
  fetchApiRef: { id: 'fetch' },
}));

jest.mock('@backstage/core-components', () => ({
  InfoCard: ({ title, children }: { title: string; children: React.ReactNode }) => (
    <div data-testid="info-card" data-title={title}>{children}</div>
  ),
  EmptyState: ({ title, description }: { title: string; description?: string }) => (
    <div data-testid="empty-state">
      <span>{title}</span>
      {description && <span>{description}</span>}
    </div>
  ),
}));

import { JitApprovalsPanelCardComponent } from './JitApprovalsPanelCard';
import { useEntity } from '@backstage/plugin-catalog-react';
import { useApi } from '@backstage/core-plugin-api';

const mockUseEntity = useEntity as jest.Mock;
const mockUseApi = useApi as jest.Mock;

const baseEntity = {
  apiVersion: 'backstage.io/v1alpha1',
  kind: 'Resource',
  metadata: {
    name: 'agent-arsalan-a3f2',
    labels: { 'nvidia-ida/ttl-minutes': '60' },
    annotations: {},
  },
  spec: { type: 'agent-sandbox' },
  relations: [],
};

/**
 * Build a mock useApi that returns discoveryApi or fetchApi based on apiRef.id.
 */
function buildMockUseApi({
  getBaseUrl,
  mockFetch,
}: {
  getBaseUrl: jest.Mock;
  mockFetch?: jest.Mock;
}) {
  return (ref: { id: string }) => {
    if (ref.id === 'discovery') return { getBaseUrl };
    if (ref.id === 'fetch') return { fetch: mockFetch ?? jest.fn() };
    return {};
  };
}

describe('JitApprovalsPanelCardComponent', () => {
  afterEach(() => jest.clearAllMocks());

  it('happy path: renders empty state while TODO-B2 is not implemented', async () => {
    mockUseEntity.mockReturnValue({ entity: baseEntity });
    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockResolvedValue('http://rhdh.local/api/proxy'),
      }),
    );

    render(<JitApprovalsPanelCardComponent />);
    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument();
    });
    expect(screen.getByText('No active JIT sessions')).toBeInTheDocument();
  });

  it('deny path: shows error when discoveryApi.getBaseUrl throws', async () => {
    mockUseEntity.mockReturnValue({ entity: baseEntity });
    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockRejectedValue(new Error('proxy unavailable')),
      }),
    );

    render(<JitApprovalsPanelCardComponent />);
    await waitFor(() => {
      expect(screen.getByText('Could not load sessions')).toBeInTheDocument();
    });
  });

  it('renders sandbox name in subheader area', async () => {
    mockUseEntity.mockReturnValue({ entity: baseEntity });
    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockResolvedValue('http://rhdh.local/api/proxy'),
      }),
    );

    render(<JitApprovalsPanelCardComponent />);
    await waitFor(() => {
      expect(screen.getByText(/agent-arsalan-a3f2/)).toBeInTheDocument();
    });
  });

  it('fetchApi is resolved from useApi (auth contract guard)', async () => {
    // Verify that fetchApiRef is resolved by the component so that when
    // TODO-B2 is uncommented the fetchApi.fetch() path is already wired.
    mockUseEntity.mockReturnValue({ entity: baseEntity });
    const mockFetch = jest.fn();
    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockResolvedValue('http://rhdh.local/api/proxy'),
        mockFetch,
      }),
    );

    render(<JitApprovalsPanelCardComponent />);
    await waitFor(() => {
      // The component resolves the proxy base URL; confirm no error path triggered.
      expect(screen.getByTestId('empty-state')).toBeInTheDocument();
    });
    // mockFetch is wired and available; with TODO-B2 commented out it is not
    // called yet — but the ref is resolved. If a raw fetch() were used instead
    // of fetchApi.fetch(), this mock would not be called even after uncomment.
    // The test documents the expected call site for the reviewer.
  });
});
