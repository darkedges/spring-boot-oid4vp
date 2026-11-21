package com.darkedges.oid4vc.tenancy;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Tenants in memory: for tests and single-instance development. Lost on restart. */
public final class InMemoryTenantRepository implements TenantRepository {

    private final Map<String, Tenant> byId = new ConcurrentHashMap<>();

    @Override
    public Optional<Tenant> findById(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    @Override
    public Optional<Tenant> findBySlug(String slug) {
        return byId.values().stream().filter(t -> t.slug().equals(slug)).findFirst();
    }

    @Override
    public List<Tenant> findAll() {
        List<Tenant> all = new ArrayList<>(byId.values());
        all.sort(Comparator.comparing(Tenant::slug));
        return all;
    }

    @Override
    public synchronized Tenant save(Tenant tenant) {
        findBySlug(tenant.slug()).filter(other -> !other.id().equals(tenant.id())).ifPresent(other -> {
            throw new SlugTakenException(tenant.slug());
        });
        byId.put(tenant.id(), tenant);
        return tenant;
    }

    @Override
    public boolean delete(String id) {
        return byId.remove(id) != null;
    }
}
