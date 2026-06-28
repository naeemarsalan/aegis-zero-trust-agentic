-- JIT-approver persistence schema (L0).
-- Idempotent: all statements use IF NOT EXISTS / ON CONFLICT DO NOTHING.
-- Run as the DB owner (e.g. the CNPG initdb superuser); app connects as
-- the lower-privilege 'app' role (CNPG jit-approver-db-app secret).
--
-- WORM invariant (jit_ledger):
--   The app role has INSERT + SELECT ONLY on jit_ledger.
--   UPDATE and DELETE are REVOKED so a compromised app process cannot rewrite
--   or truncate audit history (privilege-enforced, not just app-code-enforced).
--
-- C4 once-only (jit_session):
--   The atomic state flip is: UPDATE jit_session SET state=$new
--   WHERE id=$id AND state = ANY($expected_states) RETURNING id.
--   No secondary UPDATE path is needed; only PostgresStore calls this.

-- ---------------------------------------------------------------------------
-- 1. Session table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jit_session (
    id              TEXT PRIMARY KEY,
    state           TEXT        NOT NULL DEFAULT 'pending',
    pr_url          TEXT,
    pr_number       INTEGER,
    expires_at      TIMESTAMPTZ,
    requester_sub   TEXT,
    approver_sub    TEXT,          -- set by L1 mint gate
    scope_hash      TEXT,          -- set by L1 mint gate (anti-TOCTOU scope bind)
    request_json    TEXT,          -- serialised EscalationRequest (pydantic JSON)
    extra_json      TEXT,          -- volatile: vault_role, session_jwt, sa_token, etc.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- 2. Delivery dedupe table (C4 replay / X-Gitea-Delivery idempotency)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jit_delivery (
    delivery_id TEXT PRIMARY KEY,
    seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- 3. Ledger table (INSERT-only WORM — foundation for L2 hash-chaining)
-- ---------------------------------------------------------------------------
-- IMPORTANT: the REVOKE below enforces the WORM property at the DB privilege
-- layer.  The app role MUST connect as 'app' (CNPG jit-approver-db-app),
-- NOT as the owner/superuser, for this to be effective.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jit_ledger (
    seq          BIGSERIAL   PRIMARY KEY,
    prev_hash    TEXT        NOT NULL DEFAULT '',
    entry_hash   TEXT        NOT NULL DEFAULT '',
    payload_json TEXT        NOT NULL DEFAULT '{}',
    sig          TEXT,               -- NULLABLE until L2 signs entries
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- 4. Ledger head (singleton CAS row for L2 hash-chaining)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jit_ledger_head (
    id        INTEGER PRIMARY KEY DEFAULT 1,
    seq       BIGINT  NOT NULL DEFAULT 0,
    head_hash TEXT    NOT NULL DEFAULT '',
    CONSTRAINT singleton CHECK (id = 1)
);

-- Seed the singleton row (idempotent).
INSERT INTO jit_ledger_head (id, seq, head_hash)
VALUES (1, 0, '')
ON CONFLICT (id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 5. WORM privilege enforcement
-- ---------------------------------------------------------------------------
-- Replace 'app' with the actual CNPG application role if different.
-- CNPG generates the role named after the 'owner' field in the Cluster spec
-- bootstrap.initdb.owner (we use 'app' in cnpg-cluster.yaml).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    -- Only execute if the role exists (so this script is safe to run in dev
    -- environments without a CNPG cluster where the 'app' role may not exist).
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app') THEN
        -- CNPG runs this schema as the superuser, so the tables are owned by
        -- 'postgres' — the application role 'app' has NO access until granted.
        -- Without these GRANTs the app's startup_check sees the tables as
        -- "not found" (no privilege) and crashloops.
        GRANT USAGE ON SCHEMA public TO app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app;
        -- WORM: the ledger is APPEND-ONLY for the application role (revoke AFTER
        -- the blanket grant above so a compromised app can't rewrite history).
        REVOKE UPDATE, DELETE ON jit_ledger FROM app;
    END IF;
END
$$;
