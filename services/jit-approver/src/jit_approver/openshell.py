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


def _yaml_to_policy(doc: dict[str, Any]):
    """Convert a baseline policy YAML mapping → SandboxPolicy proto (the floor)."""
    from jit_approver.osh import sandbox_pb2 as sb

    fp = doc.get("filesystem_policy") or {}
    pol = sb.SandboxPolicy(
        version=int(doc.get("version", 1)),
        filesystem=sb.FilesystemPolicy(
            include_workdir=bool(fp.get("include_workdir", True)),
            read_only=list(fp.get("read_only", [])),
            read_write=list(fp.get("read_write", [])),
        ),
        landlock=sb.LandlockPolicy(
            compatibility=(doc.get("landlock") or {}).get("compatibility", "best_effort")
        ),
        process=sb.ProcessPolicy(
            run_as_user=(doc.get("process") or {}).get("run_as_user", "sandbox"),
            run_as_group=(doc.get("process") or {}).get("run_as_group", "sandbox"),
        ),
    )
    for key, rule in (doc.get("network_policies") or {}).items():
        nr = sb.NetworkPolicyRule(
            name=rule.get("name", key),
            endpoints=[
                sb.NetworkEndpoint(
                    host=e["host"], port=int(e.get("port", 443)),
                    protocol=e.get("protocol", "rest"), tls=e.get("tls", "terminate"),
                    enforcement=e.get("enforcement", "enforce"), access=e.get("access", "full"),
                )
                for e in rule.get("endpoints", [])
            ],
            binaries=[sb.NetworkBinary(path=b["path"]) for b in rule.get("binaries", [])],
        )
        pol.network_policies[key].CopyFrom(nr)
    return pol


def create_sandbox(name: str, policy_doc: dict[str, Any], image: str = "",
                   runtime_class: str | None = None):
    """Launch a sandbox born with the baseline floor (1b). policy_doc is the parsed
    openshell-baseline-policy ConfigMap. Returns the gateway's SandboxResponse."""
    if not available():
        raise RuntimeError("OpenShell client not configured")
    from jit_approver.osh import openshell_pb2 as ph

    tmpl = ph.SandboxTemplate(image=image)
    if runtime_class:
        tmpl.runtime_class_name = runtime_class
    spec = ph.SandboxSpec(policy=_yaml_to_policy(policy_doc), template=tmpl)
    stub, channel = _stub_and_channel()
    try:
        resp = stub.CreateSandbox(ph.CreateSandboxRequest(name=name, spec=spec), timeout=120)
        logger.info("openshell_sandbox_created", extra={"name": name})
        return resp
    finally:
        channel.close()


def network_rule_names(sandbox: str) -> list[str]:
    """Observe the named network rules currently on a sandbox's policy (floor +
    any active JIT widen). Used to prove the elevator empirically."""
    if not available():
        return []
    from jit_approver.osh import openshell_pb2 as ph

    stub, channel = _stub_and_channel()
    try:
        resp = stub.GetSandbox(ph.GetSandboxRequest(name=sandbox), timeout=15)
        return list(resp.sandbox.spec.policy.network_policies.keys())
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
