# list-firewall-rules

You have access to the `mcp__mcp-gateway__search_firewall_rules` tool, which queries the pfSense firewall rule list through the zero-trust MCP gateway.

## When to use this skill

Use this skill when the user asks to:
- List, show, or display firewall rules
- Search for specific firewall rules by interface, source IP, destination port, or description
- Summarise the current firewall policy
- Audit which rules are enabled or disabled

## Tool usage

The tool signature:

```
search_firewall_rules(
    interface: str | None = None,
    source_ip: str | None = None,
    destination_port: str | None = None,
    rule_type: str | None = None,
    disabled: bool | None = None,
    search_description: str | None = None,
    page: int = 1,
    page_size: int = 20,
    sort_by: str = "tracker"
) -> {success, page, page_size, filters_applied, count, rules[], links, timestamp}
```

All parameters are optional. A bare call with no arguments returns the full first page (up to 20 rules). Set `page_size` up to 200 for bulk retrieval.

## Read-only constraint

This tool is annotated `readOnlyHint=True`. It retrieves data only — it does NOT create, modify, or delete firewall rules. Do not attempt mutation operations through this gateway path.

## Response format

Always present the firewall rules as a clear, human-readable summary. Include:
- Total rule count (`count` field in the response)
- A numbered list of rules with: interface, source, destination, action (pass/block), description, enabled status
- Highlight any disabled rules
- Note if pagination is required (multiple pages available via `links.next`)

## Error handling

If the tool call fails (gateway 403, network error, or MCP error):
- Report the error clearly
- Do NOT retry with different credentials or attempt to escalate permissions
- State that the tool is read-only and scope-limited; request the user contact the platform team if access should be expanded
