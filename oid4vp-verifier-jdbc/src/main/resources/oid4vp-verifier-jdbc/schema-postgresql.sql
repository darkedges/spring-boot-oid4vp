-- oid4vp-verifier-jdbc: what a verifier keeps between requests, for every tenant. Idempotent; applied at start-up when
-- oid4vp.verifier.store.initialize-schema=true.
--
-- kind     request_context, ephemeral_key, transaction_result, transaction, transaction_request, transaction_answer
-- key      SHA-256 (hex) of the entry's key: a state or transaction id is a bearer secret
-- owner    SHA-256 (hex) of what the entry may only be used with: the registration key (a request, an ephemeral key), the
--          response code (a same-device result) or the tenant (a backend transaction; its answer's owner changes once its
--          result is collected). A use with anything else doesn't match the row.
-- payload  AES-256-GCM under oid4vp.verifier.store.encryption-key, bound to kind and key

CREATE TABLE IF NOT EXISTS oid4vp_verifier_entry (
    kind        varchar(32)  NOT NULL,
    key         char(64)     NOT NULL,
    owner       char(64)     NOT NULL,
    payload     bytea        NOT NULL,
    expires_at  timestamptz  NOT NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, key)
);

CREATE INDEX IF NOT EXISTS oid4vp_verifier_entry_owner ON oid4vp_verifier_entry (kind, owner);
CREATE INDEX IF NOT EXISTS oid4vp_verifier_entry_expiry ON oid4vp_verifier_entry (expires_at);
