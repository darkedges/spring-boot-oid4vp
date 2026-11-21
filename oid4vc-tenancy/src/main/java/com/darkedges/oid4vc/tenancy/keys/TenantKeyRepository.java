package com.darkedges.oid4vc.tenancy.keys;

import java.util.List;
import java.util.Optional;

/** Where tenants' keys are kept. Implementations encrypt private keys at rest. */
public interface TenantKeyRepository {

    Optional<TenantKey> findActive(String tenantId, String purpose);

    /** Active and retired keys for this purpose, newest first. */
    List<TenantKey> findPublished(String tenantId, String purpose);

    /** Every key of the tenant, newest first. */
    List<TenantKey> findAll(String tenantId);

    /**
     * Adds a new ACTIVE key.
     *
     * @return {@code false} if the tenant already has an active key for this purpose (another instance created it first)
     */
    boolean insertActive(TenantKey key);

    /** Retires the active key {@code kid} and adds {@code replacement} as active, as one change. */
    void rotate(String tenantId, String purpose, String kid, TenantKey replacement);

    /** Removes a retired key, so it is no longer published. An active key can't be removed. */
    boolean deleteRetired(String tenantId, String kid);
}
