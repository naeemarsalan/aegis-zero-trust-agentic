/**
 * Unit tests for AgentSessionReceiptCardComponent.
 * No network. discoveryApi and fetchApi are mocked.
 * Covers: no session-id (deny path), load error (deny path), summary absent (TODO-C1 placeholder),
 * and summary present (happy path).
 *
 * The component under test is the raw AgentSessionReceiptCardComponent (not the
 * createComponentExtension wrapper). Testing the wrapper would require a full
 * Backstage app context; testing the raw component is the correct unit-test
 * boundary.
 *
 * AUTH NOTE: the component uses useApi(fetchApiRef).fetch() — NOT the raw browser
 * fetch(). Tests mock fetchApiRef through useApi so that the mocked fetchApi.fetch()
 * is what the component calls. This is the correct mock boundary: it validates that
 * the component passes fetchApi.fetch through the Backstage API system rather than
 * bypassing it with a raw call.
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

import { AgentSessionReceiptCardComponent } from './AgentSessionReceiptCard';
import { useEntity } from '@backstage/plugin-catalog-react';
import { useApi } from '@backstage/core-plugin-api';

const mockUseEntity = useEntity as jest.Mock;
const mockUseApi = useApi as jest.Mock;

const entityWithoutSession = {
  apiVersion: 'backstage.io/v1alpha1',
  kind: 'Resource',
  metadata: { name: 'agent-arsalan-a3f2', annotations: {}, labels: {} },
  spec: { type: 'agent-sandbox' },
  relations: [],
};

const SESSION_ID = 'aaaabbbb-cccc-dddd-eeee-ffffffffffff';

const entityWithSession = {
  ...entityWithoutSession,
  metadata: {
    ...entityWithoutSession.metadata,
    annotations: { 'nvidia-ida/jit-session-id': SESSION_ID },
  },
};

/**
 * Build a mock useApi that returns either the discoveryApi or fetchApi stub
 * depending on which apiRef is requested.  useApi() is called with the apiRef
 * object; we identify which one by its `.id` field (set in the mock above).
 */
function buildMockUseApi({
  getBaseUrl,
  mockFetch,
}: {
  getBaseUrl: jest.Mock;
  mockFetch: jest.Mock;
}) {
  return (ref: { id: string }) => {
    if (ref.id === 'discovery') return { getBaseUrl };
    if (ref.id === 'fetch') return { fetch: mockFetch };
    return {};
  };
}

describe('AgentSessionReceiptCardComponent', () => {
  afterEach(() => jest.clearAllMocks());

  it('deny path: shows empty state when no session annotation is present', async () => {
    mockUseEntity.mockReturnValue({ entity: entityWithoutSession });
    const mockFetch = jest.fn();
    mockUseApi.mockImplementation(
      buildMockUseApi({ getBaseUrl: jest.fn(), mockFetch }),
    );

    render(<AgentSessionReceiptCardComponent />);

    await waitFor(() => {
      expect(screen.getByText('No JIT session recorded')).toBeInTheDocument();
    });
  });

  it('deny path: shows error when fetchApi.fetch throws (network error)', async () => {
    mockUseEntity.mockReturnValue({ entity: entityWithSession });
    const mockFetch = jest.fn().mockRejectedValue(new Error('network error'));
    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockResolvedValue('http://rhdh.local/api/proxy'),
        mockFetch,
      }),
    );

    render(<AgentSessionReceiptCardComponent />);

    await waitFor(() => {
      expect(screen.getByText('Could not load session')).toBeInTheDocument();
    });
  });

  it('deny path: shows error when discoveryApi.getBaseUrl throws', async () => {
    mockUseEntity.mockReturnValue({ entity: entityWithSession });
    const mockFetch = jest.fn();
    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockRejectedValue(new Error('proxy unavailable')),
        mockFetch,
      }),
    );

    render(<AgentSessionReceiptCardComponent />);

    await waitFor(() => {
      expect(screen.getByText('Could not load session')).toBeInTheDocument();
    });
  });

  it('happy path: renders session state when status returns; summary 404 is silent', async () => {
    mockUseEntity.mockReturnValue({ entity: entityWithSession });
    const mockFetch = jest.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          id: SESSION_ID,
          state: 'issued',
          pr_url: 'https://git.arsalan.io/anaeem/nvidia-ida/pulls/7',
          expires_at: '2099-06-13T14:00:00Z',
        }),
      })
      // GET /summary — 404 until TODO-C1
      .mockResolvedValueOnce({ ok: false, status: 404 });

    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockResolvedValue('http://rhdh.local/api/proxy'),
        mockFetch,
      }),
    );

    render(<AgentSessionReceiptCardComponent />);

    await waitFor(() => {
      expect(screen.getByText('issued')).toBeInTheDocument();
    });
    expect(screen.getByText('Approval PR')).toBeInTheDocument();
  });

  it('happy path: renders summary when TODO-C1 endpoint returns data', async () => {
    mockUseEntity.mockReturnValue({ entity: entityWithSession });
    const mockFetch = jest.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          id: SESSION_ID,
          state: 'expired',
          pr_url: null,
          expires_at: '2026-06-13T12:00:00Z',
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          outcome: 'completed',
          actions_taken: ['get_firewall_rules', 'add_firewall_rule'],
          errors_encountered: [],
        }),
      });

    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockResolvedValue('http://rhdh.local/api/proxy'),
        mockFetch,
      }),
    );

    render(<AgentSessionReceiptCardComponent />);

    await waitFor(() => {
      expect(screen.getByText('get_firewall_rules')).toBeInTheDocument();
    });
    expect(screen.getByText('add_firewall_rule')).toBeInTheDocument();
  });

  it('happy path: uses fetchApi.fetch (not raw browser fetch) — verifies auth contract', async () => {
    // This test verifies that the component calls fetchApi.fetch(), which is the
    // only path that attaches the Backstage JWT for the /jit-approver proxy.
    // If the component used raw fetch() instead, mockFetch would never be called.
    mockUseEntity.mockReturnValue({ entity: entityWithSession });
    const mockFetch = jest.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          id: SESSION_ID,
          state: 'issued',
          pr_url: null,
          expires_at: null,
        }),
      })
      .mockResolvedValueOnce({ ok: false, status: 404 });

    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockResolvedValue('http://rhdh.local/api/proxy'),
        mockFetch,
      }),
    );

    render(<AgentSessionReceiptCardComponent />);

    await waitFor(() => {
      // fetchApi.fetch was called at least once (status call)
      expect(mockFetch).toHaveBeenCalled();
    });
    // Verify the URL passed to fetchApi.fetch includes the proxy path
    expect(mockFetch.mock.calls[0][0]).toContain(
      `/jit-approver/requests/${SESSION_ID}/status`,
    );
  });

  it('happy path: Grafana link uses real cluster IP, not a fabricated nip.io hostname', async () => {
    mockUseEntity.mockReturnValue({ entity: entityWithSession });
    const mockFetch = jest.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          id: SESSION_ID,
          state: 'issued',
          pr_url: null,
          expires_at: null,
        }),
      })
      .mockResolvedValueOnce({ ok: false, status: 404 });

    mockUseApi.mockImplementation(
      buildMockUseApi({
        getBaseUrl: jest.fn().mockResolvedValue('http://rhdh.local/api/proxy'),
        mockFetch,
      }),
    );

    render(<AgentSessionReceiptCardComponent />);

    await waitFor(() => {
      const grafanaLink = document.querySelector('a[href="http://172.16.2.252:3000"]');
      expect(grafanaLink).toBeInTheDocument();
    });
  });
});
