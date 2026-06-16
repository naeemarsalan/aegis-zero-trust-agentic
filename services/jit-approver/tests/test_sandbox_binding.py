"""Tests for the sandbox-uid binding stamped into the JIT session JWT.

ext-proc's delegated SVID path elevates a tool only when the session JWT's
``sandbox_uid`` claim equals the SVID's sandbox_uid. These tests pin the
producer side: the claim is derived from the requesting agent's SPIFFE ID and
is present only for sandbox-pathed principals.
"""

import jwt

from jit_approver import signing


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def test_sandbox_uid_from_spiffe_parses_sandbox_path():
    sid = "spiffe://anaeem.na-launch.com/ns/agent-sandbox/sandbox/e2e0a1b2-c3d4-4e5f-8a9b-000000000001"
    assert signing.sandbox_uid_from_spiffe(sid) == "e2e0a1b2-c3d4-4e5f-8a9b-000000000001"


def test_sandbox_uid_from_spiffe_empty_for_non_sandbox():
    # SA-based SPIFFE IDs (and junk) yield no sandbox binding -> "" (fail-closed).
    assert signing.sandbox_uid_from_spiffe("spiffe://anaeem.na-launch.com/ns/agent-sandbox/sa/agent") == ""
    assert signing.sandbox_uid_from_spiffe("") == ""


def test_session_jwt_includes_sandbox_uid_when_provided():
    token = signing.mint_session_jwt(
        session_id="sess-1",
        tool_scope=["create_firewall_rule_advanced"],
        issued_at=1_700_000_000,
        duration_minutes=30,
        sandbox_uid="e2e0a1b2-c3d4-4e5f-8a9b-000000000001",
    )
    claims = _claims(token)
    assert claims["sandbox_uid"] == "e2e0a1b2-c3d4-4e5f-8a9b-000000000001"
    assert claims["tool_scope"] == ["create_firewall_rule_advanced"]


def test_session_jwt_omits_sandbox_uid_when_absent():
    token = signing.mint_session_jwt(
        session_id="sess-2",
        tool_scope=[],
        issued_at=1_700_000_000,
        duration_minutes=30,
    )
    assert "sandbox_uid" not in _claims(token)
