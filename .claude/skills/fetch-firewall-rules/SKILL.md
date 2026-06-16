---
name: fetch-firewall-rules
description: Audit or list pfSense firewall rules by calling the read-only MCP tool `search_firewall_rules` through the mcp-gateway. Use this skill whenever the goal involves inspecting, auditing, or summarising firewall rules. Read-only only — no create, update, or delete operations are permitted or attempted.
---

# Fetch Firewall Rules Skill

## When to use

Invoke this skill when the task involves any of the following:

- Listing all currently configured pfSense firewall rules.
- Auditing rules by interface, source IP, destination port, rule type, or description.
- Answering a question such as "what rules exist on WAN?", "are there any rules that allow traffic to port 443?", or "summarise the firewall policy".

Do NOT invoke this skill to:

- Create, modify, or delete firewall rules (those operations are write-scoped and blocked by the `read-only` grant).
- Perform any mutation on the pfSense host.
- Bypass a 403 or authz DENY — if the gateway returns 403, the grant scope or your SVID binding is wrong; do not retry or escalate via this skill.

## Core invariants

1. **Read-only.** The only tool called is `search_firewall_rules` (registered with `readOnlyHint=True`, `destructiveHint=False`). No other firewall tool is called from this skill.
2. **No credential handling.** You do not read, store, forward, or log the `Authorization: Bearer` header or the MCP server config. The gateway ext-proc injects the downstream pfSense credential; you never see it.
3. **No raw-arg logging.** Tool arguments must not be emitted verbatim to any log. The JSONL wrapper hashes args before emission — do not bypass this by printing args directly.
4. **Gateway only.** Calls go through the MCP server named `mcp-gateway` (URL `${MCP_GATEWAY_URL}/mcp`). Do not attempt a direct HTTP call to the pfSense host.
5. **Fail-closed on tool error.** If the tool returns `success: false` or any unexpected error structure, surface the error to the user and stop. Do not retry silently or assume the rule list is empty.

## Tool reference

| Field | Value |
|-------|-------|
| SDK tool name | `mcp__mcp-gateway__search_firewall_rules` |
| MCP tool name | `search_firewall_rules` |
| Server | `mcp-gateway` (type `http`, URL `${MCP_GATEWAY_URL}/mcp`) |
| readOnlyHint | `true` |
| destructiveHint | `false` |

All parameters are optional. A bare call with `{}` returns the first page (up to 20 rules). Use `page_size` up to 200 to widen the window; use `page` to paginate.

Available filter parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `interface` | string | Filter by interface name (e.g. `WAN`, `LAN`). |
| `source_ip` | string | Filter by source IP address. |
| `destination_port` | string | Filter by destination port. |
| `rule_type` | string | Filter by rule type. |
| `disabled` | boolean | Filter by disabled state. |
| `search_description` | string | Substring match on rule description. |
| `page` | integer | Page number (default 1). |
| `page_size` | integer | Results per page (default 20, max 200). |
| `sort_by` | string | Sort field (default `tracker`). |

Response shape: `{ success, page, page_size, filters_applied, count, rules[], links, timestamp }`.

## Procedure

### Step 1 — Determine filters

Review the user's request and identify any filters that narrow the query:

- If the user asks about a specific interface, set `interface`.
- If the user asks about a specific IP or port, set `source_ip` or `destination_port`.
- If the user asks for a broad audit with no specific filter, call with `{}` (no arguments) and increase `page_size` to 200 if a full list is needed.

Construct the argument object. Do not include parameters not relevant to the request.

### Step 2 — Call `search_firewall_rules`

Call the tool through the gateway:

```
tool: mcp__mcp-gateway__search_firewall_rules
args: { <filters from Step 1> }
```

The `allowed_tools` list for this session already includes `mcp__mcp-gateway__search_firewall_rules`. No additional escalation is needed.

If the response contains `"success": false`, read the error message, report it to the user, and stop. Do not attempt a fallback tool.

### Step 3 — Paginate if needed

Check the response `count` and `links` fields. If `count` exceeds the page returned, repeat Step 2 with incremented `page` values until all pages are retrieved. Keep a running accumulator of the `rules[]` arrays.

Maximum pages to fetch in one skill invocation: 10 (i.e. at most 2000 rules with `page_size=200`). If the rule set exceeds this, surface a truncation notice in the summary.

### Step 4 — Summarise

Produce a concise, human-readable summary of the retrieved rules. The summary MUST include:

- Total rule count returned.
- Any filters that were applied (`filters_applied` from the response).
- A table or grouped list of rules with the following columns at minimum: tracker, interface, source, destination, port, action (allow/block/reject), description, disabled (yes/no).
- Highlight any rules that are disabled or that have an atypical action (e.g. reject rather than block).

The summary is emitted as a `type="assistant"` JSONL line. Raw rule JSON must not be emitted verbatim as a log line — summarise in natural language or a markdown table.

### Step 5 — No follow-on writes

After the summary is produced, the skill is complete. Do not call any tool that modifies state (create, update, delete, bulk operations). If the user subsequently requests a write operation, that request is outside the scope of this skill and outside the `read-only` grant; surface that constraint explicitly.
