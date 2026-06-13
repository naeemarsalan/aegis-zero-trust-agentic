/**
 * ConsentPage tests.
 *
 * Tests run without any network access (no cluster, no catalog API).
 * The fetchApi mock controls what the catalog returns.
 *
 * Coverage:
 *   - Happy path: capabilities resolved, Proceed button enabled after checkbox
 *   - Error path: catalog fetch failure renders ErrorPanel
 *   - Missing query params: renders ErrorPanel with guidance
 *   - Deny/Abandon: navigates back (no API call)
 *   - JIT badge: shown when jit-required=true, absent for read-only caps
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

// ---------------------------------------------------------------------------
// Backstage API mocks
// ---------------------------------------------------------------------------

const mockFetch = jest.fn();
const mockGetBaseUrl = jest.fn().mockResolvedValue('http://localhost:7007/api/catalog');

jest.mock('@backstage/core-plugin-api', () => ({
  useApi: (ref: { id: string }) => {
    if (ref.id === 'discovery') return { getBaseUrl: mockGetBaseUrl };
    if (ref.id === 'fetch') return { fetch: mockFetch };
    return {};
  },
  discoveryApiRef: { id: 'discovery' },
  fetchApiRef: { id: 'fetch' },
  createPlugin: jest.fn(),
  createRoutableExtension: jest.fn(),
  createRouteRef: jest.fn(),
}));

jest.mock('@backstage/core-components', () => ({
  Page: ({ children }: { children: React.ReactNode }) => <div data-testid="page">{children}</div>,
  Header: ({ title, subtitle }: { title: string; subtitle?: React.ReactNode }) => (
    <div data-testid="header">
      <span>{title}</span>
      {subtitle && <div data-testid="header-subtitle">{subtitle}</div>}
    </div>
  ),
  Content: ({ children }: { children: React.ReactNode }) => <div data-testid="content">{children}</div>,
  InfoCard: ({ title, children, subheader }: { title: string; children: React.ReactNode; subheader?: React.ReactNode; noPadding?: boolean; style?: React.CSSProperties }) => (
    <div data-testid={`card-${title.replace(/\s/g, '-').toLowerCase()}`}>
      <div>{title}</div>
      {subheader && <div data-testid="card-subheader">{subheader}</div>}
      {children}
    </div>
  ),
  Progress: () => <div data-testid="progress" />,
  ErrorPanel: ({ title, error }: { title: string; error: Error }) => (
    <div data-testid="error-panel">
      <span>{title}</span>
      <span>{error.message}</span>
    </div>
  ),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

import { ConsentPage } from './ConsentPage';

function mockCatalogEntity(name: string, tier: 'read-only' | 'privileged', jitRequired: boolean) {
  return {
    metadata: {
      name,
      title: `${name} Title`,
      description: `${name} description`,
      labels: {
        'nvidia-ida/capability-tier': tier,
        'nvidia-ida/jit-required': String(jitRequired),
      },
      annotations: {
        'nvidia-ida/mcp-endpoint': `https://mcp-gateway.apps.anaeem.na-launch.com/${name}`,
        'nvidia-ida/tools-read-only': 'get_*, list_*',
        'nvidia-ida/tools-privileged': tier === 'privileged' ? 'create_*, delete_*' : 'none',
      },
    },
  };
}

function renderConsentPage(search: string) {
  return render(
    <MemoryRouter initialEntries={[`/agent-consent${search}`]}>
      <Routes>
        <Route path="/agent-consent" element={<ConsentPage />} />
        <Route path="/catalog/default/resource/:name" element={<div data-testid="entity-page">entity-page</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ConsentPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGetBaseUrl.mockResolvedValue('http://localhost:7007/api/catalog');
  });

  // ── Happy path ──────────────────────────────────────────────────────────

  it('renders sandbox summary and capability manifest on happy path', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockCatalogEntity('mcp-echo', 'read-only', false),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockCatalogEntity('mcp-pfsense', 'privileged', true),
      });

    renderConsentPage(
      '?sandbox=agent-arsalan-a3f2&scope=read-write&ttl=60&capabilities=mcp-echo,mcp-pfsense&goal=test+goal&owner=user:default/arsalan',
    );

    // Sandbox summary card renders
    expect(screen.getByText('agent-arsalan-a3f2')).toBeInTheDocument();
    expect(screen.getByText('60 minutes (requested)')).toBeInTheDocument();
    expect(screen.getByText('user:default/arsalan')).toBeInTheDocument();

    // Capability rows appear after catalog resolves
    await waitFor(() => {
      expect(screen.getByText('mcp-echo Title')).toBeInTheDocument();
      expect(screen.getByText('mcp-pfsense Title')).toBeInTheDocument();
    });

    // Tier badges
    expect(screen.getByText('read-only · auto')).toBeInTheDocument();
    expect(screen.getByText('privileged · needs-approval')).toBeInTheDocument();

    // JIT badge visible for privileged cap
    expect(screen.getByText(/JIT · 60m/)).toBeInTheDocument();
  });

  it('enables Proceed button only after checkbox is checked', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => mockCatalogEntity('mcp-echo', 'read-only', false),
    });

    renderConsentPage(
      '?sandbox=agent-test-0001&scope=read-only&ttl=30&capabilities=mcp-echo',
    );

    await waitFor(() => expect(screen.getByText('mcp-echo Title')).toBeInTheDocument());

    const proceedBtn = screen.getByRole('button', { name: /Proceed to workspace/i });
    expect(proceedBtn).toBeDisabled();

    const checkbox = screen.getByRole('checkbox');
    fireEvent.click(checkbox);
    expect(proceedBtn).not.toBeDisabled();
  });

  it('navigates to entity page when Proceed is clicked', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => mockCatalogEntity('mcp-echo', 'read-only', false),
    });

    renderConsentPage(
      '?sandbox=agent-arsalan-a3f2&scope=read-only&ttl=15&capabilities=mcp-echo',
    );

    await waitFor(() => expect(screen.getByText('mcp-echo Title')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: /Proceed to workspace/i }));

    await waitFor(() => {
      expect(screen.getByTestId('entity-page')).toBeInTheDocument();
    });
  });

  // ── Error paths ─────────────────────────────────────────────────────────

  it('shows ErrorPanel when catalog fetch fails', async () => {
    mockFetch.mockRejectedValue(new Error('network timeout'));

    renderConsentPage(
      '?sandbox=agent-arsalan-fail&scope=read-only&ttl=30&capabilities=mcp-echo',
    );

    await waitFor(() => {
      expect(screen.getByTestId('error-panel')).toBeInTheDocument();
      expect(screen.getByText(/Failed to load capability details from catalog/)).toBeInTheDocument();
    });
  });

  it('shows capability-not-found message for 404 entity', async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 404 });

    renderConsentPage(
      '?sandbox=agent-test-404&scope=read-only&ttl=30&capabilities=mcp-nonexistent',
    );

    await waitFor(() => {
      expect(
        screen.getByText(/Capability not found in catalog/),
      ).toBeInTheDocument();
    });
  });

  it('shows ErrorPanel when sandbox query param is missing', () => {
    // No query params at all
    renderConsentPage('');

    expect(screen.getByTestId('error-panel')).toBeInTheDocument();
    expect(screen.getByText(/Missing query parameters/)).toBeInTheDocument();
  });

  // ── Abandon / Deny ───────────────────────────────────────────────────────

  it('calls window.history.back on Abandon click (no API call)', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => mockCatalogEntity('mcp-echo', 'read-only', false),
    });

    const backSpy = jest.spyOn(window.history, 'back').mockImplementation(() => {});

    renderConsentPage(
      '?sandbox=agent-test-0001&scope=read-only&ttl=30&capabilities=mcp-echo',
    );

    await waitFor(() => expect(screen.getByText('mcp-echo Title')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /Abandon/i }));
    expect(backSpy).toHaveBeenCalledTimes(1);

    // Confirm no DELETE call was made (no teardown endpoint exists)
    expect(mockFetch).not.toHaveBeenCalledWith(
      expect.stringContaining('/sandboxes/'),
      expect.any(Object),
    );

    backSpy.mockRestore();
  });

  // ── JIT badge visibility ─────────────────────────────────────────────────

  it('shows no JIT badge for a fully read-only capability', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => mockCatalogEntity('mcp-echo', 'read-only', false),
    });

    renderConsentPage(
      '?sandbox=agent-ro-test&scope=read-only&ttl=60&capabilities=mcp-echo',
    );

    await waitFor(() => expect(screen.getByText('mcp-echo Title')).toBeInTheDocument());
    expect(screen.queryByText(/JIT/)).not.toBeInTheDocument();
  });

  it('shows JIT badge with duration for a privileged capability', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => mockCatalogEntity('mcp-pfsense', 'privileged', true),
    });

    renderConsentPage(
      '?sandbox=agent-priv-test&scope=read-write&ttl=45&capabilities=mcp-pfsense',
    );

    await waitFor(() => expect(screen.getByText('mcp-pfsense Title')).toBeInTheDocument());
    expect(screen.getByText(/JIT · 45m/)).toBeInTheDocument();
  });
});
