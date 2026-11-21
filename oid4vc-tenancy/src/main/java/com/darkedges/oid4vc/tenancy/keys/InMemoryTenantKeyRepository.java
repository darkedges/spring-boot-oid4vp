package com.darkedges.oid4vc.tenancy.keys;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/** Keys in memory: for tests and single-instance development. Every key is lost on restart. */
public final class InMemoryTenantKeyRepository implements TenantKeyRepository {

    private final List<TenantKey> keys = new ArrayList<>();

    @Override
    public synchronized Optional<TenantKey> findActive(String tenantId, String purpose) {
        return keys.stream().filter(k -> k.tenantId().equals(tenantId) && k.purpose().equals(purpose)
                && k.status() == TenantKey.Status.ACTIVE).findFirst();
    }

    @Override
    public synchronized List<TenantKey> findPublished(String tenantId, String purpose) {
        return keys.stream().filter(k -> k.tenantId().equals(tenantId) && k.purpose().equals(purpose))
                .sorted(Comparator.comparing(TenantKey::createdAt).reversed()).toList();
    }

    @Override
    public synchronized List<TenantKey> findAll(String tenantId) {
        return keys.stream().filter(k -> k.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(TenantKey::createdAt).reversed()).toList();
    }

    @Override
    public synchronized boolean insertActive(TenantKey key) {
        if (findActive(key.tenantId(), key.purpose()).isPresent()) return false;
        keys.add(key);
        return true;
    }

    @Override
    public synchronized void rotate(String tenantId, String purpose, String kid, TenantKey replacement) {
        TenantKey current = findActive(tenantId, purpose).filter(k -> k.kid().equals(kid))
                .orElseThrow(() -> new IllegalStateException("the active key changed meanwhile"));
        keys.remove(current);
        keys.add(current.retired(Instant.now()));
        keys.add(replacement);
    }

    @Override
    public synchronized boolean deleteRetired(String tenantId, String kid) {
        return keys.removeIf(k -> k.tenantId().equals(tenantId) && k.kid().equals(kid) && k.status() == TenantKey.Status.RETIRED);
    }
}
