#!/usr/bin/env python3
"""Local SVID-injecting brain-auth proxy (credential-less LLM reasoning).

PROBLEM
-------
The Claude Agent SDK spawns the system ``claude`` CLI, which posts to
``{ANTHROPIC_BASE_URL}/v1/messages`` with a STATIC ``Authorization: Bearer
${ANTHROPIC_AUTH_TOKEN}`` (or ``x-api-key``). The agent must hold NO model
credential — its only identity is its SPIFFE JWT-SVID, which is short-lived and
must be fetched FRESH per request. A static env token cannot carry a rotating
SVID, so we cannot point the CLI straight at the MaaS gateway.

SOLUTION
--------
Run this tiny stdlib-only forward proxy on 127.0.0.1 inside the sandbox. The
``claude`` CLI is pointed at it (``ANTHROPIC_BASE_URL=http://127.0.0.1:<port>``)
with a throw-away token. For EVERY request this proxy:

  1. STRIPS the CLI's inbound Authorization / x-api-key (the throw-away token —
     the agent holds no real key).
  2. Fetches a FRESH JWT-SVID via agent_harness.svid_bearer.fetch_agent_svid()
     (the same selection logic / shape-guard the MCP path uses).
  3. Rewrites the Anthropic path ``/v1/messages`` -> the MaaS route prefix
     ``/openrouter/messages``. The MaaS HTTPRoute URLRewrites ``/openrouter`` ->
     ``/v1`` so upstream OpenRouter sees ``/api/v1/messages`` (Anthropic-native).
  4. Forwards to the in-cluster MaaS gateway with the SVID as
     ``Authorization: Bearer <svid>`` and ``Host: <maas vhost>`` so Authorino
     (maas-spiffe-auth) validates the SVID and authorizes the sandbox subject.

The upstream OpenRouter key is injected SERVER-SIDE by the MaaS llm-proxy from
Vault — it NEVER reaches this process or the agent.

ENV
---
MAAS_BRAIN_LISTEN_PORT   default 8787 (loopback only)
MAAS_GATEWAY_URL         default http://maas-gateway-istio.maas.svc:80
MAAS_GATEWAY_HOST        default maas.apps.ocp-dev.na-launch.com (vhost / SNI-less Host)
MAAS_ROUTE_PREFIX        default /openrouter (the MaaS standard-tier route)
(SVID selection env is read by svid_bearer: SVID_JWT_PATH, SPIFFE_ENDPOINT_SOCKET,
 SVID_REQUIRE_PATH_SUBSTR, ...)

SECURITY
--------
- Binds 127.0.0.1 ONLY — never reachable off-pod.
- The SVID is held in memory per-request, set as the upstream Authorization, and
  never logged. Inbound client credentials are dropped, never forwarded.
"""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Import the SAME SVID fetcher the MCP path uses (shape-guard + retry included).
from agent_harness.svid_bearer import fetch_agent_svid

LISTEN_PORT = int(os.environ.get("MAAS_BRAIN_LISTEN_PORT", "8787"))
GATEWAY_URL = os.environ.get(
    "MAAS_GATEWAY_URL", "http://maas-gateway-istio.maas.svc:80"
).rstrip("/")
GATEWAY_HOST = os.environ.get("MAAS_GATEWAY_HOST", "maas.apps.ocp-dev.na-launch.com")
ROUTE_PREFIX = os.environ.get("MAAS_ROUTE_PREFIX", "/openrouter").rstrip("/")

# Headers carrying the CLI's (throw-away) credential or hop-by-hop fields that
# must NOT be forwarded; we set our own Authorization + Host.
_STRIP = {
    "authorization", "x-api-key", "host", "content-length",
    "connection", "proxy-authorization",
}


def _map_path(path: str) -> str:
    """Map the CLI's Anthropic path onto the MaaS route.

    The CLI hits ``/v1/messages`` (optionally ``?beta=true`` etc.). The MaaS
    standard route is ``/openrouter`` and URLRewrites its prefix to ``/v1`` ->
    upstream ``/api/v1/messages`` (OpenRouter's Anthropic-compatible endpoint).
    So ``/v1/messages`` -> ``/openrouter/messages``. Query string preserved.
    """
    p = path
    # The CLI posts to /v1/<sub>; strip the leading /v1 and graft the route prefix.
    if p.startswith("/v1/"):
        sub = p[len("/v1"):]            # -> /messages[?...]
        return ROUTE_PREFIX + sub        # -> /openrouter/messages[?...]
    if p == "/v1":
        return ROUTE_PREFIX
    # Anything else: pass through under the route prefix (defensive).
    return ROUTE_PREFIX + (p if p.startswith("/") else "/" + p)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A002
        # Log method+path+status only; never headers/body (no SVID/credential).
        sys.stderr.write("maas-brain-proxy %s\n" % (fmt % args))

    def _err(self, code, msg):
        import json
        data = json.dumps({"type": "error", "error": {"type": "proxy_error", "message": msg}}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _forward(self):
        # Fetch a FRESH SVID per request (the agent's only identity).
        try:
            svid = fetch_agent_svid()
        except Exception as exc:  # noqa: BLE001
            self._err(503, "SVID fetch failed: %s" % type(exc).__name__)
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""

        url = GATEWAY_URL + _map_path(self.path)
        fwd = {k: v for k, v in self.headers.items() if k.lower() not in _STRIP}
        fwd["Authorization"] = "Bearer " + svid
        fwd["Host"] = GATEWAY_HOST
        fwd.setdefault("Content-Type", "application/json")
        del svid

        req = urllib.request.Request(url, data=body, headers=fwd, method=self.command)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
                self.send_response(resp.status)
                ctype = resp.headers.get("Content-Type", "application/json")
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as exc:
            data = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as exc:  # noqa: BLE001
            self._err(502, "upstream error: %s" % exc)

    def do_POST(self):
        self._forward()

    def do_GET(self):
        if self.path in ("/healthz", "/health"):
            self._err(200, "ok") if False else self._ok()
            return
        self._forward()

    def _ok(self):
        import json
        data = json.dumps({"status": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), Handler)
    sys.stderr.write(
        "maas-brain-proxy listening on 127.0.0.1:%d -> %s%s (Host: %s)\n"
        % (LISTEN_PORT, GATEWAY_URL, ROUTE_PREFIX, GATEWAY_HOST)
    )
    srv.serve_forever()


if __name__ == "__main__":
    main()
