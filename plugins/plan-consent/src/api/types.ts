/**
 * API types for the plan-consent plugin.
 *
 * All types here are derived from the REAL service contracts in this repo:
 *   services/sandbox-launcher/src/sandbox_launcher/models.py  — LaunchResponse
 *   services/jit-approver/src/jit_approver/models.py          — SessionStatus, EscalationRequest
 *   platform/devhub/catalog/*.yaml                            — capability entity labels
 *
 * Types annotated TODO-A1 correspond to the not-yet-existing POST /plans
 * endpoint on sandbox-launcher (see data-contracts research, TODO-A1).
 * Until that endpoint exists the ConsentPage renders these shapes populated
 * from query-parameter data passed by the scaffolder template.
 */

// ---------------------------------------------------------------------------
// Shapes derived from LaunchResponse (REAL — POST /launch 202)
// Fields: sandbox_name, sandbox_id, namespace, phase, conversation_url,
//         access_hint, owner
// ---------------------------------------------------------------------------

export interface LaunchResponse {
  /** Stable sandbox name: agent-<username>-<short-uuid> */
  sandbox_name: string;
  /** UUID from OpenShell gateway */
  sandbox_id: string;
  /** Always "openshell" (SANDBOX_NAMESPACE env) */
  namespace: string;
  /** PROVISIONING at creation time */
  phase: string;
  /**
   * Public conversation URL — ALWAYS null at creation time.
   * ExposeService gRPC is never called by sandbox-launcher on the /launch path.
   * TODO-D1: add POST /sandboxes/{name}/expose to sandbox-launcher.
   */
  conversation_url: string | null;
  /** oc exec command to reach the agent shell */
  access_hint: string;
  /** Verified or advisory entity ref of the sandbox owner */
  owner: string;
}

// ---------------------------------------------------------------------------
// Shapes derived from SessionStatus (REAL — GET /requests/{id}/status)
// Fields: id, state, pr_url, expires_at, session_jwt*, sa_token*, tool_scope*
// ---------------------------------------------------------------------------

export type SessionState =
  | 'pending'
  | 'approved'
  | 'issued'
  | 'expired'
  | 'denied';

export interface SessionStatus {
  id: string;
  state: SessionState;
  /** Forgejo PR URL; null until PR is created */
  pr_url: string | null;
  /** ISO-8601 UTC — set only when state === 'issued' */
  expires_at: string | null;
  /** Present only when state === 'issued' */
  session_jwt: string | null;
  /** Present only when state === 'issued' */
  sa_token: string | null;
  /** Present only when state === 'issued' */
  tool_scope: string[] | null;
}

// ---------------------------------------------------------------------------
// Capability entity shape — read from Backstage catalog REST API
//
// REAL: GET /api/catalog/entities/by-name/resource/default/{name}
//       returns a Backstage Entity; the fields below are drawn from the REAL
//       catalog entities in platform/devhub/catalog/pfsense.yaml and echo.yaml.
//
// Labels confirmed real:
//   nvidia-ida/capability-tier   "read-only" | "privileged"
//   nvidia-ida/jit-required      "true" | "false"
//   nvidia-ida/transport         "streamable-http"
//
// Annotations confirmed real:
//   nvidia-ida/mcp-endpoint      e.g. "https://mcp-gateway.apps.anaeem.na-launch.com/mcp"
//   nvidia-ida/tools-read-only   comma-free description string
//   nvidia-ida/tools-privileged  comma-free description string
// ---------------------------------------------------------------------------

export interface CapabilityMeta {
  /** Catalog entity name (e.g. "mcp-pfsense", "mcp-echo") */
  name: string;
  /** Human title from metadata.title */
  title: string;
  /** metadata.description */
  description: string;
  /**
   * "read-only" | "privileged"
   * From label: nvidia-ida/capability-tier
   */
  tier: 'read-only' | 'privileged';
  /**
   * Whether JIT approval is needed for any tool in this capability.
   * From label: nvidia-ida/jit-required  ("true" | "false")
   */
  jitRequired: boolean;
  /** From annotation: nvidia-ida/mcp-endpoint */
  mcpEndpoint: string;
  /** From annotation: nvidia-ida/tools-read-only (raw string) */
  toolsReadOnly: string;
  /** From annotation: nvidia-ida/tools-privileged (raw string) */
  toolsPrivileged: string;
}

// ---------------------------------------------------------------------------
// TODO-A1: PlanResponse — shape returned by POST /plans (NOT YET IMPLEMENTED)
//
// This endpoint does not exist on sandbox-launcher. Until it does, the
// plan-consent page reads all these fields from scaffolder output query params.
// When TODO-A1 is implemented, replace the query-param parsing in
// usePlanData() with a fetch to /api/proxy/mcp-launcher/plans.
//
// Endpoint:  POST /api/proxy/mcp-launcher/plans
// Body:      { goal, capabilities, mode, scope, ttl_minutes, user }
// Response:  PlanResponse (shape below)
// Does:      Validates inputs; returns structured pre-launch manifest without
//            provisioning anything; ephemeral 60-second server-side TTL.
// ---------------------------------------------------------------------------

export interface PlanResponse {
  /** Server-generated plan ID (UUID) — passed to POST /launch as plan_id */
  plan_id: string;
  goal: string;
  capabilities: string[];
  scope: string;
  ttl_minutes: number;
  /**
   * Inferred tool list from the capability entities.
   * Populated server-side from catalog; mirrors what ext-proc will enforce.
   */
  estimated_tools: string[];
  /**
   * Static summary of the baseline deny-by-default floor.
   * Derived from platform/openshell/policies/baseline.yaml at plan time.
   */
  network_floor: string;
  /**
   * Requested policy widenings (host:port pairs).
   * Populated from the capability entities' policy_delta if known at plan time.
   */
  policy_delta: Array<{ host: string; port: number }>;
  /** Seconds until this plan record expires on the server */
  expires_in_seconds: number;
}

// ---------------------------------------------------------------------------
// Query-param shape — what the scaffolder output link delivers
//
// The scaffolder template outputs a link:
//   /agent-consent?sandbox=<name>&scope=<scope>&ttl=<minutes>&capabilities=<csv>
//   &goal=<url-encoded-goal>&owner=<entity-ref>
//
// These are the ONLY guaranteed fields at plan-consent page load time
// (LaunchResponse fields come from the POST /launch 202 body, which is
// surfaced via the scaffolder output text block, not directly queryable by
// the consent page).
// ---------------------------------------------------------------------------

export interface ConsentQueryParams {
  sandbox: string;
  scope: string;
  ttl: string;
  /** Comma-separated capability entity names */
  capabilities: string;
  goal?: string;
  owner?: string;
}
