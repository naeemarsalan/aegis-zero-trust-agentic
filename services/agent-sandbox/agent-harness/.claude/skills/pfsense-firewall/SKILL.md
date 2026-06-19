---
name: pfsense-firewall
description: Read and change pfSense firewall rules through the zero-trust gateway using the mcp-call helper. Reads return immediately; writes (create/add/modify) pause for a human to approve in the console, then continue automatically. Use whenever the task involves listing, auditing, OR changing firewall rules.
---

# pfSense firewall operations (zero-trust, no credentials)

You run inside a credential-less sandbox. You hold ONLY your SPIFFE identity. You
do NOT have any direct/native firewall MCP tools. The ONLY way to reach pfSense is
the **`mcp-call`** helper, run via the **Bash** tool. The platform resolves your
identity to the consenting user and injects the real credential server-side — you
never see or handle a credential.

## The one and only mechanism: `mcp-call`

```bash
mcp-call <tool_name> '<json-arguments>'
```
- No native MCP firewall tools exist for you. Always use `mcp-call` via Bash.
- `mcp-call` with no arguments runs a read (`search_firewall_rules`).

## Reads (allowed immediately)

```bash
mcp-call                      # list firewall rules (search_firewall_rules)
mcp-call search_firewall_rules '{"interface":"lan"}'
```

## Writes / changes (require human approval — handled for you)

```bash
mcp-call create_firewall_rule_advanced '{"interface":"lan","rule_type":"pass","protocol":"tcp","source":"any","destination":"any","description":"<why>"}'
```
What happens automatically inside `mcp-call`:
1. The write is DENIED at first (read-only baseline) — expected, not a failure.
2. It files a scoped, time-boxed approval request (a Gitea PR) on your behalf.
3. **It then PAUSES** while a human approves it in the approval console. This can
   take a few minutes — that is NORMAL. Do NOT abort, do NOT try another tool, do
   NOT give up. Just wait for the command to return.
4. On approval it automatically retries and completes under a distinct write
   identity. If a valid approval already exists, it proceeds immediately.

Because the wait can take minutes, run the write with a generous Bash timeout (set
timeout to 600000 ms / 10 minutes). If it ultimately returns `403`/`denied`, the
request was rejected or timed out — report that and stop; do not escalate further.

Required args for `create_firewall_rule_advanced`: `interface`, `rule_type`
(pass/block/reject), `protocol` (tcp/udp/icmp/any), `source`, `destination`
(use `description` — not `descr` — for the human label).

## Invariants you must honour
- Never attempt to obtain, read, copy, or pass any credential. The gateway handles identity.
- Use ONLY `mcp-call` for pfSense — you have no other firewall tools.
- Request only the write you actually need; one approval covers that tool for its window.
- Always report what you did (or why a write was denied) clearly to the user.
