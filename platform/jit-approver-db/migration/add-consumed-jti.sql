-- Migration: add consumed_jti table for ADR-0014 single-use jti consume-on-use.
--
-- Purpose:
--   jit-gate atomically INSERTs into consumed_jti before authorising a single-use-class
--   tool call.  ON CONFLICT DO NOTHING returns rowcount=0 on a replay → DENY.
--   This makes replay-protection multi-replica-safe: any jit-gate pod that loses the
--   INSERT race denies the duplicate call.  RFC 9449 section 11.1 rationale.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS; safe to run on a cluster that already has
-- the table (e.g. a re-apply after a migration retry).
--
-- Run as the CNPG initdb superuser (same role as schema.sql) OR via
-- platform/jit-approver-db/base/schema-initdb-configmap.yaml postInitApplicationSQLRefs.
-- For a live cluster with jit-approver-db already running, apply via:
--   kubectl exec -it -n mcp-gateway jit-approver-db-1 -- psql -U postgres jit_approver \
--     -f /path/to/add-consumed-jti.sql
--
-- Keep in sync with:
--   services/jit-approver/src/jit_approver/persistence/schema.sql  (source of truth)
--   platform/jit-approver-db/base/schema-initdb-configmap.yaml     (CNPG bootstrap copy)
--
-- Security note: the 'app' role (jit-gate's connection) MUST have INSERT + SELECT on this
-- table but not UPDATE or DELETE (single-use: once written, a row is immutable until
-- the TTL-based reaper prunes it).  The REVOKE below enforces this at the DB privilege
-- layer so a compromised gate process cannot un-consume a jti.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS consumed_jti (
    jti         TEXT        NOT NULL,
    tool        TEXT        NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Composite PK: a jti may theoretically cover multiple tools in the future
    -- (not today; current ADR-0014 scope has one tool per single-use session).
    -- Using (jti, tool) allows the gate to do a targeted ON CONFLICT check per tool
    -- without needing a separate index.
    PRIMARY KEY (jti, tool)
);

-- Index consumed_at to support the TTL reaper:
--   DELETE FROM consumed_jti WHERE consumed_at < now() - INTERVAL '30 minutes';
-- 30 minutes covers the maximum capability TTL (reuse_window = 30 min); any row
-- older than that is expired and safe to prune.
CREATE INDEX IF NOT EXISTS consumed_jti_consumed_at_idx
    ON consumed_jti (consumed_at);

-- WORM-like privilege enforcement: the app role may INSERT (to consume a jti) and
-- SELECT (to check existence) but NOT UPDATE or DELETE (an attacker who can write
-- to this table should not be able to un-consume a jti and replay the call).
-- Periodic reaper pruning (rows > 30 min old) runs as a maintenance task, not as
-- the app role.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app') THEN
        GRANT INSERT, SELECT ON consumed_jti TO app;
        REVOKE UPDATE, DELETE ON consumed_jti FROM app;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Schema.sql sync: copy the block above into
--   services/jit-approver/src/jit_approver/persistence/schema.sql
-- after the jit_ledger_head INSERT block, BEFORE the closing WORM DO block.
-- Then copy the CREATE TABLE + CREATE INDEX + DO block into
--   platform/jit-approver-db/base/schema-initdb-configmap.yaml
-- under the data.schema.sql key (append after the existing jit_ledger_head
-- INSERT block).
-- ---------------------------------------------------------------------------
