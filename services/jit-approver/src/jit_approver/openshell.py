"""OpenShell gateway gRPC client — the JIT "request changes" elevator for the
OpenShell *policy boundary* (the sibling of the MCP tool gate and the Vault SA
token).

A sandboxed agent's standing network egress is the deny-by-default baseline floor
(platform/openshell/policies/baseline.yaml → ConfigMap openshell-baseline-policy).
When an approved JIT grant carries a network policy_delta, jit-approver calls the
OpenShell gateway's UpdateConfig RPC with an incremental AddNetworkRule merge op to
widen *that one sandbox* for the grant window, and RemoveNetworkRule to revert on
expiry — time-boxed and auto-reverting, exactly like the ephemeral SA token.

Connection: mTLS gRPC to the in-cluster gateway (openshell.openshell.svc:8080) using
the openshell-client-tls cert. The client is OPTIONAL: if it can't be configured
(certs/addr absent) the elevator is disabled and a network policy_delta is a no-op
warning — issuance of the SA token + session JWT still proceeds (fail-soft on the
policy leg, since the MCP gate + Vault scope are the hard controls).
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("jit_approver.openshell")

# JIT-added network rules are namespaced with this prefix so revert is unambiguous
# and a grant can never touch the baseline's own named rules.
RULE_PREFIX = "jit-"


def _config() -> dict[str, str] | None:
    """Resolve gateway address + mTLS cert paths from env. None disables the leg."""
    addr = os.environ.get("OPENSHELL_GATEWAY_ADDR", "openshell.openshell.svc:8080")
    cert_dir = os.environ.get("OPENSHELL_CLIENT_TLS_DIR", "/etc/openshell-client-tls")
    ca, crt, key = (
        os.path.join(cert_dir, f) for f in ("ca.crt", "tls.crt", "tls.key")
    )
    if not all(os.path.exists(p) for p in (ca, crt, key)):
        return None
    return {"addr": addr, "ca": ca, "crt": crt, "key": key}


def available() -> bool:
    return _config() is not None


def _stub_and_channel():
    import grpc  # local import so jit-approver runs without grpc when the leg is off

    from jit_approver.osh import openshell_pb2_grpc as gw

    cfg = _config()
    if cfg is None:
        raise RuntimeError("OpenShell client TLS not configured")
    creds = grpc.ssl_channel_credentials(
        root_certificates=open(cfg["ca"], "rb").read(),
        private_key=open(cfg["key"], "rb").read(),
        certificate_chain=open(cfg["crt"], "rb").read(),
    )
    # The server cert is for the in-cluster service name; the gRPC default
    # authority matches openshell.openshell.svc, so no override is needed when
    # OPENSHELL_GATEWAY_ADDR uses that hostname.
    channel = grpc.secure_channel(cfg["addr"], creds)
    return gw.OpenShellStub(channel), channel


def _network_endpoint(host: str, port: int):
    from jit_approver.osh import sandbox_pb2 as sb

    return sb.NetworkEndpoint(
        host=host,
        port=int(port),
        protocol="rest",
        tls="terminate",
        enforcement="enforce",
        access="full",
    )


def widen_network(session_id: str, sandbox: str, endpoints: list[dict[str, Any]],
                  binaries: list[str] | None = None) -> bool:
    """Add a JIT-scoped network rule to ``sandbox`` allowing egress to ``endpoints``
    ([{host, port}, ...]). Returns True on success, False if the leg is disabled.

    Idempotent-ish: the rule is named jit-<session_id>; re-adding replaces it.
    """
    if not available():
        logger.warning("openshell_elevator_disabled", extra={"session_id": session_id})
        return False
    import grpc
    from jit_approver.osh import openshell_pb2 as ph, sandbox_pb2 as sb

    rule_name = f"{RULE_PREFIX}{session_id}"
    bins = [sb.NetworkBinary(path=p) for p in (binaries or ["/sandbox-agent", "/usr/bin/curl"])]
    rule = sb.NetworkPolicyRule(
        name=rule_name,
        endpoints=[_network_endpoint(e["host"], e["port"]) for e in endpoints],
        binaries=bins,
    )
    op = ph.PolicyMergeOperation(add_rule=ph.AddNetworkRule(rule_name=rule_name, rule=rule))
    req = ph.UpdateConfigRequest(name=sandbox, merge_operations=[op])
    stub, channel = _stub_and_channel()
    try:
        stub.UpdateConfig(req, timeout=30)
        logger.info("openshell_widen_ok", extra={
            "session_id": session_id, "sandbox": sandbox, "rule": rule_name,
            "endpoints": [f"{e['host']}:{e['port']}" for e in endpoints]})
        return True
    except grpc.RpcError as exc:
        logger.error("openshell_widen_failed", extra={
            "session_id": session_id, "sandbox": sandbox,
            "code": str(exc.code()), "detail": exc.details()})
        raise
    finally:
        channel.close()


def revert_network(session_id: str, sandbox: str) -> bool:
    """Remove the JIT-scoped network rule from ``sandbox`` — back to the baseline
    floor. Called by the reaper on expiry. Tolerates "already gone"."""
    if not available():
        return False
    import grpc
    from jit_approver.osh import openshell_pb2 as ph

    rule_name = f"{RULE_PREFIX}{session_id}"
    op = ph.PolicyMergeOperation(remove_rule=ph.RemoveNetworkRule(rule_name=rule_name))
    req = ph.UpdateConfigRequest(name=sandbox, merge_operations=[op])
    stub, channel = _stub_and_channel()
    try:
        stub.UpdateConfig(req, timeout=30)
        logger.info("openshell_revert_ok", extra={
            "session_id": session_id, "sandbox": sandbox, "rule": rule_name})
        return True
    except grpc.RpcError as exc:
        # NOT_FOUND == already reverted (sandbox gone / rule absent) — idempotent.
        if exc.code() == grpc.StatusCode.NOT_FOUND:
            return True
        logger.error("openshell_revert_failed", extra={
            "session_id": session_id, "sandbox": sandbox,
            "code": str(exc.code()), "detail": exc.details()})
        raise
    finally:
        channel.close()
