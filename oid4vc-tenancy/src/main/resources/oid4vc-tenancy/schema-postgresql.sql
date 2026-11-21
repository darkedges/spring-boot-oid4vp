-- oid4vc-tenancy: tenants and their keys. Idempotent; applied at start-up when oid4vc.tenancy.store.initialize-schema=true.

CREATE TABLE IF NOT EXISTS oid4vc_tenant (
    id              varchar(64)  PRIMARY KEY,           -- the AuthStack environment id
    organization_id varchar(64),
    slug            varchar(63)  NOT NULL UNIQUE,
    enabled         boolean      NOT NULL DEFAULT true,
    settings        jsonb        NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oid4vc_tenant_key (
    tenant_id    varchar(64)  NOT NULL REFERENCES oid4vc_tenant (id) ON DELETE CASCADE,
    kid          varchar(64)  NOT NULL,
    purpose      varchar(32)  NOT NULL,
    status       varchar(16)  NOT NULL,                 -- ACTIVE or RETIRED
    public_jwk   text         NOT NULL,
    private_key  bytea        NOT NULL,                 -- AES-256-GCM under the deployment's key-encryption key
    certificate  bytea        NOT NULL,                 -- DER
    created_at   timestamptz  NOT NULL,
    retired_at   timestamptz,
    PRIMARY KEY (tenant_id, kid)
);

-- At most one active key per tenant and purpose: two instances creating the first key at once cannot both win.
CREATE UNIQUE INDEX IF NOT EXISTS oid4vc_tenant_key_one_active
    ON oid4vc_tenant_key (tenant_id, purpose) WHERE status = 'ACTIVE';
